from __future__ import annotations
from typing import List

class Component(object):
    @property
    def parent(self) -> Component:
        return self._parent

    @parent.setter
    def parent(self, parent: Component):
        self._parent = parent

    def add(self, component: Component) -> None:
        pass

    def remove(self, component: Component) -> None:
        pass

    def is_composite(self) -> bool:
        return False

    def to_json(self) -> dict:
        pass
    
    def jsonfy(self) -> dict:
        pass


class Leaf(Component):
    @property
    def path(self) -> str:
        return self._path

    @path.setter
    def path(self, path: str):
        self._path = path
    
    # Fill Other Attributes
    def to_json(self) -> dict:
        return {};

    def jsonfy(self) -> dict:
        result = self.to_json()
        result["content"] = {"path": self.path()}
        return result
    
class Composite(Component):
    def __init__(self) -> None:
        self._children: List[Component] = []

    def add(self, component: Component) -> None:
        self._children.append(component)
        component.parent = self

    def remove(self, component: Component) -> None:
        self._children.remove(component)
        component.parent = None
    
    def is_composite(self) -> bool:
        return True

    def jsonfy(self):
        result = self.to_json();
        content = []
        for child in self._children:
            content.append(child.jsonfy())
        result["content"] = content
        