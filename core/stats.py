from typing import Dict, Any, Optional, List, Iterable, Tuple
from datetime import datetime, timedelta
import base64, time
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base
from HLL import HyperLogLog

from core.conn import Conn
from core.client import Client
from core.models import User
from util.json_type import JSONType

HOURS_KEPT = 48
DAYS_KEPT = 35

class Stats:
	__slots__ = (
		'logged_in', 'by_client', '_conn', '_client_id_cache', 'started', '_day', '_day_stats', '_pending_days', '_past_days',
		'_hours', '_peak_record', '_collect_hour',
	)
	
	logged_in: int
	by_client: Dict[int, Dict[str, Any]]
	_conn: Conn
	_client_id_cache: Optional[Dict[Client, int]]
	started: datetime
	_day: int
	_day_stats: Dict[str, Any]
	_pending_days: Dict[int, Dict[str, Any]]
	_past_days: Dict[int, bytes]
	_hours: Dict[int, Dict[str, Any]]
	_peak_record: Dict[str, Any]
	_collect_hour: int
	
	def __init__(self, conn: Conn) -> None:
		self.logged_in = 0
		self.by_client = {}
		self._conn = conn
		self._client_id_cache = None
		self.started = datetime.utcnow()
		self._day = _current_day()
		self._day_stats = _new_day_stats()
		self._pending_days = {}
		self._past_days = {}
		self._hours = {}
		self._peak_record = { 'value': 0, 'at': None }
		self._collect_hour = _current_hour()
		
		self._load_rollups()
		
		hour = _current_hour()
		with self._conn.session() as sess:
			current = sess.query(CurrentStats).filter(CurrentStats.key == 'current_hour').one_or_none()
			if not current:
				return
			if current.value['hour'] != hour:
				return
			self.by_client = {
				int(client_id): _stats_from_json(stats)
				for client_id, stats in current.value['by_client'].items()
			}
	
	def _load_rollups(self) -> None:
		with self._conn.session() as sess:
			for row in sess.query(CurrentStats).filter(CurrentStats.key.in_(['hours', 'peak_record'])):
				if row.key == 'hours' and isinstance(row.value, dict):
					self._hours = { int(hour): dict(entry) for hour, entry in row.value.items() }
				elif row.key == 'peak_record' and isinstance(row.value, dict):
					self._peak_record = { 'value': int(row.value.get('value') or 0), 'at': row.value.get('at') }
			oldest = _day_key(self._day - DAYS_KEPT)
			for row in sess.query(CurrentStats).filter(CurrentStats.key.like('day:%'), CurrentStats.key >= oldest):
				try:
					day = int(row.key[4:])
				except ValueError:
					continue
				if day == self._day:
					self._day_stats = _day_from_json(row.value)
				elif row.value.get('users_active'):
					self._past_days[day] = base64.b64decode(row.value['users_active'])
	
	def on_login(self) -> None:
		self._roll_day()
		self.logged_in += 1
		self._day_stats['logins'] += 1
	
	def on_logout(self) -> None:
		self.logged_in -= 1
	
	def on_online(self, online: int) -> None:
		self._roll_day()
		now = _iso(datetime.utcnow())
		if online > self._day_stats['peak']:
			self._day_stats['peak'] = online
			self._day_stats['peak_at'] = now
		hour_entry = self._hour_entry(_current_hour())
		if online > hour_entry['peak']:
			hour_entry['peak'] = online
		if online > self._peak_record['value']:
			self._peak_record = { 'value': online, 'at': now }
	
	def on_user_active(self, user: User, client: Client) -> None:
		self._collect('users_active', user, client)
	
	def on_message_sent(self, user: User, client: Client) -> None:
		self._collect('messages_sent', user, client)
	
	def on_message_received(self, user: User, client: Client) -> None:
		self._collect('messages_received', user, client)
	
	def _collect(self, stat: str, user: User, client: Client) -> None:
		assert user is not None
		assert client is not None
		if self.by_client is None:
			self.by_client = {}
		bc = self.by_client
		client_id = self._get_client_id(client)
		if client_id not in bc:
			bc[client_id] = {}
		bhc = bc[client_id]
		if stat == 'users_active':
			if stat not in bhc:
				bhc[stat] = HyperLogLog(12)
			bhc[stat].add(user.email)
		else:
			if stat not in bhc:
				bhc[stat] = 0
			bhc[stat] += 1
		
		self._roll_day()
		if stat == 'users_active':
			self._day_stats['users_active'].add(user.email)
		else:
			self._day_stats[stat] += 1
	
	def _roll_day(self) -> None:
		day = _current_day()
		if day == self._day:
			return
		self._pending_days[self._day] = self._day_stats
		self._past_days[self._day] = bytes(self._day_stats['users_active'].registers())
		for old in [d for d in self._past_days if d < day - DAYS_KEPT]:
			del self._past_days[old]
		self._day = day
		self._day_stats = _new_day_stats()
	
	def _hour_entry(self, hour: int) -> Dict[str, Any]:
		if hour not in self._hours:
			self._hours[hour] = { 'users_active': 0, 'messages_sent': 0, 'messages_received': 0, 'peak': 0 }
		return self._hours[hour]
	
	def flush(self, online: Optional[int] = None) -> None:
		hour = _current_hour()
		now = datetime.utcnow()
		if online is not None:
			self.on_online(online)
		self._roll_day()
		
		with self._conn.session() as sess:
			current = sess.query(CurrentStats).filter(CurrentStats.key == 'logged_in').one_or_none()
			if not current:
				current = CurrentStats(key = 'logged_in')
			current.date_updated = now
			current.value = (online if online is not None else self.logged_in)
			sess.add(current)
			sess.flush()
			
			current = sess.query(CurrentStats).filter(CurrentStats.key == 'current_hour').one_or_none()
			if not current:
				current = CurrentStats(key = 'current_hour', value = { 'hour': hour })
			
			cs_hour = current.value['hour']
			current.date_updated = now
			current.value = self._flush_to_hourly(sess, cs_hour)
			self._update_hour_totals(cs_hour)
			
			if cs_hour != hour:
				self.by_client = {}
				current.value = { 'hour': hour, 'by_client': {} }
				self._collect_hour = hour
			sess.add(current)
			
			self._flush_rollups(sess, now)
	
	def _update_hour_totals(self, hour: int) -> None:
		entry = self._hour_entry(hour)
		entry['users_active'] = _hll_union(
			bytes(stats['users_active'].registers()) for stats in self.by_client.values() if 'users_active' in stats
		)
		entry['messages_sent'] = sum(int(stats.get('messages_sent') or 0) for stats in self.by_client.values())
		entry['messages_received'] = sum(int(stats.get('messages_received') or 0) for stats in self.by_client.values())
	
	def _flush_rollups(self, sess: Any, now: datetime) -> None:
		hour = _current_hour()
		for old in [h for h in self._hours if h <= hour - HOURS_KEPT]:
			del self._hours[old]
		_put(sess, 'hours', { str(h): entry for h, entry in self._hours.items() }, now)
		_put(sess, 'peak_record', self._peak_record, now)
		for day, stats in list(self._pending_days.items()) + [(self._day, self._day_stats)]:
			_put(sess, _day_key(day), _day_to_json(stats), now)
		self._pending_days.clear()
		sess.query(CurrentStats).filter(
			CurrentStats.key.like('day:%'), CurrentStats.key < _day_key(self._day - DAYS_KEPT),
		).delete(synchronize_session = False)
	
	def _flush_to_hourly(self, sess: Any, hour: int) -> Dict[str, Any]:
		for client_id, stats in self.by_client.items():
			hcs_opt = sess.query(HourlyClientStats).filter(HourlyClientStats.hour == hour, HourlyClientStats.client_id == client_id).one_or_none()
			if hcs_opt is None:
				hcs = HourlyClientStats(hour = hour, client_id = client_id)
			else:
				hcs = hcs_opt
			hcs.messages_sent = stats.get('messages_sent') or 0
			hcs.messages_received = stats.get('messages_received') or 0
			if 'users_active' in stats:
				hcs.users_active = stats['users_active'].cardinality()
			else:
				hcs.users_active = 0
			sess.add(hcs)
		return {
			'hour': hour,
			'by_client': {
				client_id: _stats_to_json(stats)
				for client_id, stats in self.by_client.items()
			}
		}
	
	def snapshot(self) -> Dict[str, Any]:
		self._roll_day()
		hour = _current_hour()
		self._update_hour_totals(self._collect_hour)
		today_registers = bytes(self._day_stats['users_active'].registers())
		
		def active_since(days: int) -> int:
			return _hll_union([today_registers] + [regs for day, regs in self._past_days.items() if day > self._day - days])
		
		current = self._hour_entry(hour)
		hourly = []
		for h in range(hour - 23, hour + 1):
			entry = self._hours.get(h) or {}
			hourly.append({
				'hour': _iso(datetime.utcfromtimestamp(h * 3600)),
				'users_active': int(entry.get('users_active') or 0), 'messages_sent': int(entry.get('messages_sent') or 0),
				'messages_received': int(entry.get('messages_received') or 0), 'peak': int(entry.get('peak') or 0),
			})
		return {
			'active': {
				'hour': int(current['users_active']),
				'today': _hll_union([today_registers]),
				'week': active_since(7),
				'month': active_since(30),
			},
			'messages': {
				'hour': { 'sent': int(current['messages_sent']), 'received': int(current['messages_received']) },
				'today': { 'sent': int(self._day_stats['messages_sent']), 'received': int(self._day_stats['messages_received']) },
			},
			'logins_today': int(self._day_stats['logins']),
			'peak_today': { 'value': int(self._day_stats['peak']), 'at': self._day_stats['peak_at'] },
			'peak_record': dict(self._peak_record),
			'hourly': hourly,
			'by_client_hourly': self._by_client_hourly(hour - 23),
			'started': _iso(self.started),
			'uptime': int((datetime.utcnow() - self.started).total_seconds()),
		}
	
	def _by_client_hourly(self, since_hour: int) -> List[Dict[str, Any]]:
		clients = { client_id: Client.ToJSON(client) for client, client_id in (self._client_id_cache or {}).items() }
		by_hour: dict[int, dict[int, dict[str, int]]] = {}
		with self._conn.session() as sess:
			if len(clients) < sess.query(sa.func.count(DBClient.id)).scalar():
				clients = { row.id: row.data for row in sess.query(DBClient).all() }
			for hcs in sess.query(HourlyClientStats).filter(HourlyClientStats.hour >= since_hour):
				by_hour.setdefault(int(hcs.hour), {})[int(hcs.client_id)] = {
					'users_active': int(hcs.users_active), 'messages_sent': int(hcs.messages_sent), 'messages_received': int(hcs.messages_received),
				}
		for client_id, stats in self.by_client.items():
			by_hour.setdefault(self._collect_hour, {})[client_id] = {
				'users_active': int(stats['users_active'].cardinality()) if 'users_active' in stats else 0,
				'messages_sent': int(stats.get('messages_sent') or 0), 'messages_received': int(stats.get('messages_received') or 0),
			}
		return [
			{
				'hour': _iso(datetime.utcfromtimestamp(h * 3600)),
				'clients': sorted(
					({ 'client': clients.get(client_id), **values } for client_id, values in by_hour[h].items()),
					key = lambda entry: -entry['users_active'],
				),
			}
			for h in sorted(by_hour, reverse = True)
		]
	
	def snapshot_started(self) -> str:
		return _iso(self.started)
	
	def uptime(self) -> int:
		return int((datetime.utcnow() - self.started).total_seconds())
	
	def _get_client_id(self, client: Client) -> int:
		if self._client_id_cache is None:
			with self._conn.session() as sess:
				self._client_id_cache = {
					Client.FromJSON(row.data): row.id
					for row in sess.query(DBClient).all()
				}
		if client not in self._client_id_cache:
			with self._conn.session() as sess:
				dbobj = DBClient(data = Client.ToJSON(client))
				sess.add(dbobj)
				sess.flush()
				self._client_id_cache[client] = dbobj.id
		return self._client_id_cache[client]

def collect_snapshot(backend: Any) -> Dict[str, Any]:
	sessions = list(backend._sc.iter_sessions())
	users: set[str] = set()
	visible: set[str] = set()
	by_program: dict[str, int] = {}
	by_client: dict[Client, int] = {}
	for bs in sessions:
		users.add(bs.user.uuid)
		if not bs.user.status.substatus.is_offlineish():
			visible.add(bs.user.uuid)
		by_program[bs.client.program] = by_program.get(bs.client.program, 0) + 1
		by_client[bs.client] = by_client.get(bs.client, 0) + 1
	snapshot = backend._stats.snapshot()
	snapshot['online'] = {
		'sessions': len(sessions),
		'users': len(users),
		'visible_users': len(visible),
		'by_program': [{ 'program': program, 'sessions': count } for program, count in sorted(by_program.items(), key = lambda item: -item[1])],
		'by_client': [
			{ **Client.ToJSON(client), 'sessions': count }
			for client, count in sorted(by_client.items(), key = lambda item: -item[1])[:20]
		],
	}
	snapshot.update(_db_counts())
	snapshot['generated'] = _iso(datetime.utcnow())
	return snapshot

_counts_cache: tuple[float, dict[str, Any]] = (0.0, {})

def _db_counts() -> Dict[str, Any]:
	global _counts_cache
	if time.monotonic() - _counts_cache[0] < 60:
		return _counts_cache[1]
	import core.db as db
	now = datetime.utcnow()
	day_ago = now - timedelta(days = 1)
	week_ago = now - timedelta(days = 7)
	count = sa.func.count
	with db.Session() as sess:
		counts = {
			'accounts': {
				'total': sess.query(count(db.User.id)).scalar() or 0,
				'new_today': sess.query(count(db.User.id)).filter(db.User.date_created >= day_ago).scalar() or 0,
				'new_week': sess.query(count(db.User.id)).filter(db.User.date_created >= week_ago).scalar() or 0,
				'verified': sess.query(count(db.User.id)).filter(db.User.account_verified == True).scalar() or 0,
				'in_directory': sess.query(count(db.User.id)).filter(db.User.show_in_dir == True).scalar() or 0,
			},
			'circles': sess.query(count(db.Circle.id)).scalar() or 0,
			'beacon': {
				'posts_today': sess.query(count(db.Activity.id)).filter(db.Activity.user_uuid.isnot(None), db.Activity.date_created >= day_ago).scalar() or 0,
				'reactions_today': sess.query(count(db.ActivityReaction.id)).filter(db.ActivityReaction.date_created >= day_ago).scalar() or 0,
				'comments_today': sess.query(count(db.ActivityComment.id)).filter(db.ActivityComment.date_created >= day_ago).scalar() or 0,
			},
		} # type: Dict[str, Any]
	_counts_cache = (time.monotonic(), counts)
	return counts

def _hll_union(register_sets: Iterable[bytes]) -> int:
	merged: bytearray | None = None
	for registers in register_sets:
		if merged is None:
			merged = bytearray(registers)
		else:
			merged = bytearray(map(max, merged, registers))
	if merged is None:
		return 0
	hll = HyperLogLog(12)
	hll.set_registers(merged)
	return int(round(hll.cardinality()))

def _new_day_stats() -> Dict[str, Any]:
	return { 'users_active': HyperLogLog(12), 'messages_sent': 0, 'messages_received': 0, 'logins': 0, 'peak': 0, 'peak_at': None }

def _day_to_json(stats: Dict[str, Any]) -> Dict[str, Any]:
	return {
		'users_active': base64.b64encode(bytes(stats['users_active'].registers())).decode('ascii'),
		'users_active_count': int(round(stats['users_active'].cardinality())),
		'messages_sent': stats['messages_sent'], 'messages_received': stats['messages_received'], 'logins': stats['logins'],
		'peak': stats['peak'], 'peak_at': stats['peak_at'],
	}

def _day_from_json(json: Dict[str, Any]) -> Dict[str, Any]:
	stats = _new_day_stats()
	if json.get('users_active'):
		stats['users_active'].set_registers(bytearray(base64.b64decode(json['users_active'])))
	for key in ('messages_sent', 'messages_received', 'logins', 'peak'):
		stats[key] = int(json.get(key) or 0)
	stats['peak_at'] = json.get('peak_at')
	return stats

def _put(sess: Any, key: str, value: Any, now: datetime) -> None:
	row = sess.query(CurrentStats).filter(CurrentStats.key == key).one_or_none()
	if row is None:
		row = CurrentStats(key = key)
	row.value = value
	row.date_updated = now
	sess.add(row)

def _day_key(day: int) -> str:
	return 'day:{:06d}'.format(day)

def _iso(dt: datetime) -> str:
	return dt.replace(microsecond = 0).isoformat() + 'Z'

def _stats_to_json(stats: Dict[str, Any]) -> Dict[str, Any]:
	json = {}
	if 'messages_sent' in stats:
		json['messages_sent'] = stats['messages_sent']
	if 'messages_received' in stats:
		json['messages_received'] = stats['messages_received']
	if 'users_active' in stats:
		json['users_active'] = list(stats['users_active'].registers())
	return json

def _stats_from_json(json: Dict[str, Any]) -> Dict[str, Any]:
	stats = {}
	if 'messages_sent' in json:
		stats['messages_sent'] = json['messages_sent']
	if 'messages_received' in json:
		stats['messages_received'] = json['messages_received']
	if 'users_active' in json:
		hll = HyperLogLog(12)
		hll.set_registers(bytearray(json['users_active']))
		stats['users_active'] = hll
	return stats

def _current_hour() -> int:
	now = datetime.utcnow()
	ts = now.timestamp()
	return int(ts // 3600)

def _current_day() -> int:
	return _current_hour() // 24

class Base(declarative_base()): # type: ignore
	__abstract__ = True

class DBClient(Base):
	__tablename__ = 'client'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True, autoincrement = True)
	data = sa.Column(JSONType, nullable = False)

class HourlyClientStats(Base):
	__tablename__ = 'stats_hour_client'
	
	hour = sa.Column(sa.BigInteger, nullable = False, primary_key = True)
	client_id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	users_active = sa.Column(sa.Integer, nullable = False, server_default = sa.text('0'))
	messages_sent = sa.Column(sa.Integer, nullable = False, server_default = sa.text('0'))
	messages_received = sa.Column(sa.Integer, nullable = False, server_default = sa.text('0'))
	
	__table_args__ = (
		sa.Index('idx_hour', 'hour'),
	)

class CurrentStats(Base):
	__tablename__ = 'stats_current'
	
	key = sa.Column(sa.String(255), nullable = False, primary_key = True)
	date_updated = sa.Column(sa.DateTime, nullable = False, server_default = sa.text('CURRENT_TIMESTAMP'))
	value = sa.Column(JSONType, nullable = False, default = {})
