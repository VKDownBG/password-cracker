from abc import ABC, abstractmethod
from typing import Optional


class CrackingStrategy(ABC):
    @abstractmethod
    def execute(self,
                target_hash: str,
                algorithm: Optional[str] = None,
                salt: str = "",
                verbose: bool = False,
                processes: int = 1,
                hex_salt: bool = False,
                salt_position: str = 'after',
                **kwargs
                ) -> Optional[str]:
        pass
