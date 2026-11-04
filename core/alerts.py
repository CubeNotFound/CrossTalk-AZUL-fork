from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit
from xml.sax.saxutils import escape, quoteattr
import itertools, re, time

import settings

SITE_IDS = { 'stocks': 0, 'calendar': 1, 'bell': 2 }
ALIGNMENTS = ('left', 'center', 'right')
AGENTS = ('email', 'messenger', 'mobile')
MAX_BODY = 1024
MAX_TEXT = 1000
MSNP_NOT = 5
MSNP_TEXTX = 9

Run = Tuple[str, bool, bool]
Line = List[Run]
Paragraph = List[Line]

_next_id = itertools.count(int(time.time()) % 0xFFFFFFFF)

def new_alert_id() -> int:
	return next(_next_id) % 0x100000000

class AlertError(ValueError):
	field: str

	def __init__(self, field: str, message: str) -> None:
		super().__init__(message)
		self.field = field

def parse_rich(markup: str) -> List[Paragraph]:
	paragraphs: list[Paragraph] = []
	text = markup.replace('\r\n', '\n').replace('\r', '\n').strip()
	for block in re.split(r'\n[ \t]*\n\s*', text):
		if not block.strip():
			continue
		bold = italic = False
		lines: list[Line] = []
		for raw in block.split('\n'):
			runs: Line = []
			buf = ''
			i = 0
			while i < len(raw):
				ch = raw[i]
				if ch == '\\' and i + 1 < len(raw):
					buf += raw[i + 1]
					i += 2
					continue
				if ch == '*':
					if buf:
						runs.append((buf, bold, italic))
						buf = ''
					if raw.startswith('**', i):
						bold = not bold
						i += 2
					else:
						italic = not italic
						i += 1
					continue
				buf += ch
				i += 1
			if buf:
				runs.append((buf, bold, italic))
			lines.append(runs)
		paragraphs.append(lines)
	return paragraphs

def plain_text(paragraphs: List[Paragraph]) -> str:
	return '\n\n'.join('\n'.join(''.join(run[0] for run in line) for line in para) for para in paragraphs)

def textx_document(paragraphs: List[Paragraph], align: str = 'left') -> str:
	attrs = '' if align == 'left' else ' align="{}"'.format(align)
	out = []
	for para in paragraphs:
		lines = []
		for line in para:
			parts = []
			for text, bold, italic in line:
				part = escape(text)
				if italic:
					part = '<I>' + part + '</I>'
				if bold:
					part = '<B>' + part + '</B>'
				parts.append(part)
			lines.append(''.join(parts))
		out.append('<P{}>{}</P>'.format(attrs, '<BR/>'.join(lines)))
	return ''.join(out)

def irc_lines(paragraphs: List[Paragraph]) -> List[str]:
	out = []
	for para in paragraphs:
		for line in para:
			parts = []
			bold = italic = False
			for text, run_bold, run_italic in line:
				if run_bold != bold:
					parts.append('\x02')
					bold = run_bold
				if run_italic != italic:
					parts.append('\x1d')
					italic = run_italic
				parts.append(text)
			if bold or italic:
				parts.append('\x0f')
			if ''.join(parts).strip():
				out.append(''.join(parts))
	return out

def _origin(url: str) -> Optional[str]:
	parts = urlsplit(url)
	if parts.scheme not in ('http', 'https') or not parts.netloc:
		return None
	return '{}://{}'.format(parts.scheme, parts.netloc)

def check_url(url: str, field: str) -> str:
	url = url.strip()
	if url and _origin(url) is None:
		raise AlertError(field, 'Links have to be full http:// or https:// addresses.')
	if len(url) > 500:
		raise AlertError(field, 'That address is too long.')
	return url

@dataclass
class Alert:
	text: str
	rich: Optional[str] = None
	align: str = 'left'
	url: str = ''
	subscr_url: str = ''
	icon: str = ''
	kind: str = 'bell'
	lang: int = 1033
	priority: int = 1
	message_id: int = 0
	via: Optional[str] = None
	email_text: Optional[str] = None
	id: int = field(default_factory = new_alert_id)

	def __post_init__(self) -> None:
		self.text = (self.text or '').strip()
		self.rich = (self.rich or '').strip() or None
		if self.rich and not self.text:
			self.text = plain_text(parse_rich(self.rich))

	def check(self, *, emailed: bool = False) -> 'Alert':
		if not self.text:
			raise AlertError('text', 'Write the alert first.')
		if len(self.text) > MAX_TEXT:
			raise AlertError('text', 'Alerts can be at most {} characters.'.format(MAX_TEXT))
		if self.align not in ALIGNMENTS:
			raise AlertError('align', 'Alignment is left, center or right.')
		if self.kind not in SITE_IDS:
			raise AlertError('kind', 'The icon is bell, stocks or calendar (or a custom icon).')
		if self.via is not None and self.via not in AGENTS:
			raise AlertError('via', 'An alert comes from e-mail, messenger or mobile.')
		if not (0 < self.lang < 0x10000):
			raise AlertError('lang', 'The language is a Windows LCID, like 1033 for English (United States).')
		if not (0 <= self.priority <= 0xFFFFFFFF and 0 <= self.message_id <= 0xFFFFFFFF):
			raise AlertError('priority', 'Priority and message ID are 32-bit numbers.')
		self.url = check_url(self.url, 'url')
		self.subscr_url = check_url(self.subscr_url, 'subscr_url')
		self.icon = check_url(self.icon, 'icon')
		size = len(self._body(self.locations()[3], MSNP_TEXTX, emailed).replace('\n', '\r\n').encode('utf-8'))
		if size > MAX_BODY:
			raise AlertError('rich' if self.rich else 'text', 'That\'s too long for Messenger: an alert\'s body can be at most {} bytes, and this one is {}.'.format(MAX_BODY, size))
		return self

	@property
	def paragraphs(self) -> List[Paragraph]:
		return parse_rich(self.rich) if self.rich else [[[(line, False, False)] for line in para.split('\n')] for para in re.split(r'\n\s*\n', self.text)]

	@property
	def site_id(self) -> int:
		return SITE_IDS[self.kind]

	@property
	def link(self) -> str:
		return self.url or settings.ALERT_SITE_URL

	def plain(self) -> str:
		return plain_text(parse_rich(self.rich)) if self.rich else self.text

	def plain_with_link(self) -> str:
		return self.plain() + ('\n' + self.url if self.url else '')

	def locations(self) -> Tuple[str, str, str, str]:
		action = self.link
		subscr = self.subscr_url or action
		icon = self.icon
		urls = [u for u in (action, subscr, icon) if u]
		origins = { _origin(u) for u in urls }
		if len(origins) == 1 and None not in origins:
			origin = origins.pop()
			assert origin is not None
			rel = lambda u: u[len(origin) + 1:] if u else ''
			return (origin + '/', rel(action), rel(subscr), rel(icon))
		return ('', action, subscr, icon)

	def _body(self, icon: str, dialect: int, emailed: bool) -> str:
		attrs = ' lang="{}"'.format(self.lang)
		if icon:
			attrs += ' icon={}'.format(quoteattr(icon))
		parts = ['<TEXT>{}</TEXT>'.format(escape(self.text))]
		if emailed and self.email_text:
			parts.append('<EMAILTEXT>{}</EMAILTEXT>'.format(escape(self.email_text)))
		if dialect >= MSNP_TEXTX and (self.rich or self.align != 'left'):
			parts.append('<TEXTX>{}</TEXTX>'.format(escape(textx_document(self.paragraphs, self.align))))
		return '<BODY{}>\n\t\t\t{}\n\t\t</BODY>'.format(attrs, '\n\t\t\t'.join(parts))

	def notification(self, *, pid: str, name: str, dialect: int, email: Optional[str] = None) -> bytes:
		siteurl, action, subscr, icon = self.locations()
		to_attrs = 'pid={} name={}'.format(quoteattr(pid), quoteattr(name))
		if email:
			to_attrs += ' email={}'.format(quoteattr(email))
		if self.via:
			to = '<TO {}>\n\t\t<VIA agent={} />\n\t</TO>'.format(to_attrs, quoteattr(self.via))
		else:
			to = '<TO {} />'.format(to_attrs)
		doc = (
			'<NOTIFICATION ver="1" id="{id}" siteid="{siteid}" siteurl={siteurl}>\n'
			'\t{to}\n'
			'\t<MSG pri="{pri}" id="{mid}">\n'
			'\t\t<ACTION url={action} />\n'
			'\t\t<SUBSCR url={subscr} />\n'
			'\t\t{body}\n'
			'\t</MSG>\n'
			'</NOTIFICATION>'
		).format(
			id = self.id, siteid = self.site_id, siteurl = quoteattr(siteurl), to = to, pri = self.priority, mid = self.message_id,
			action = quoteattr(action), subscr = quoteattr(subscr), body = self._body(icon, dialect, bool(email)),
		)
		return doc.replace('\n', '\r\n').encode('utf-8')

	def summary(self) -> Dict[str, Any]:
		return {
			'id': self.id, 'text': self.text, 'rich': self.rich, 'align': self.align, 'url': self.url, 'subscr_url': self.subscr_url,
			'icon': self.icon, 'kind': self.kind, 'lang': self.lang, 'priority': self.priority, 'via': self.via,
		}

def puid(high: int, low: int) -> str:
	return '0x{:08x}:0x{:08x}'.format(high, low)
