from app.schemas.generation import ClarificationAnswer


MAX_CLARIFICATION_ROUNDS = 3


class ClarificationService:
    def get_questions(
        self,
        description: str,
        clarifications: list[ClarificationAnswer],
    ) -> list[str]:
        if len(clarifications) >= MAX_CLARIFICATION_ROUNDS:
            return []

        text = self._combined_text(description, clarifications)
        questions: list[str] = []

        if len(description.split()) < 8:
            questions.append("Can you describe the agent's purpose in more detail?")

        if not self._mentions_target_user(text):
            questions.append("Who is the target user for this agent?")

        if not self._mentions_tone(text):
            questions.append("What tone should the agent use?")

        if not self._mentions_domain(text):
            questions.append("What domain or industry should this agent focus on?")

        asked_questions = {item.question.lower().strip() for item in clarifications}

        new_questions = [
            question
            for question in questions
            if question.lower().strip() not in asked_questions
        ]

        return new_questions[:2]

    def _combined_text(
        self,
        description: str,
        clarifications: list[ClarificationAnswer],
    ) -> str:
        answers = " ".join(item.answer for item in clarifications)
        return f"{description} {answers}".lower()

    def _mentions_target_user(self, text: str) -> bool:
        keywords = [
            "student",
            "developer",
            "founder",
            "marketer",
            "team",
            "business",
            "user",
        ]
        return any(keyword in text for keyword in keywords)

    def _mentions_tone(self, text: str) -> bool:
        keywords = [
            "friendly",
            "formal",
            "casual",
            "technical",
            "professional",
            "simple",
        ]
        return any(keyword in text for keyword in keywords)

    def _mentions_domain(self, text: str) -> bool:
        keywords = [
            "education",
            "edtech",
            "marketing",
            "finance",
            "health",
            "startup",
            "software",
            "research",
            "business",
        ]
        return any(keyword in text for keyword in keywords)
