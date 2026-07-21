"""
FalseAlarm — AI Base Provider
"""

from abc import ABC, abstractmethod

class AIProvider(ABC):
    """Abstract base class for AI Providers (Gemini, OpenAI, etc.)."""

    def __init__(self, api_key: str):
        self.api_key = api_key

    @abstractmethod
    async def analyze(self, data: dict, prompt: str) -> str:
        """Analyze the scan data and return a markdown formatted response.
        
        Args:
            data: The scan results dictionary.
            prompt: The specific instruction/prompt for the LLM.
            
        Returns:
            String containing the AI's response.
        """
        pass
