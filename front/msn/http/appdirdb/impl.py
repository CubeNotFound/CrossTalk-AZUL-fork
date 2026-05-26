from typing import Dict, Any
import json
from pathlib import Path

class DB:
	def __init__(self):
		dir_path = Path(__file__).parent  # Change 'dir' to 'dir_path'

		self.categories = [
		Category(c)
		for c in json.loads((dir_path / 'category.json').read_text())
		]

		app_dir = dir_path / 'app'  # Change 'dir' to 'dir_path'
		self.apps = {
			locale.name: [
				App(json.loads(f.read_text()), locale.name)
				for f in (app_dir / locale).glob('*.json')
			] for locale in (app_dir).iterdir() if locale.is_dir()
		}

class Base:
	def __init__(self, json: Dict[str, Any]) -> None:
		self.__dict__.update(json)

class Category(Base): pass
class App(Base):
	def __init__(self, json: Dict[str, Any], locale: str) -> None:
		super().__init__(json)
		self.locale = (None if locale == 'none' else locale)