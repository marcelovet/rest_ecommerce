from pydantic import BaseModel


class ScopeModel(BaseModel):
    read: dict[str, str]
    create: dict[str, str]
    update: dict[str, str]
    delete: dict[str, str]

    def fmt_scope(self) -> str:
        """
        Format scope for  use in JWT claims
        """
        scope_dict = self.model_dump()
        return " ".join(
            [
                f"{permission}:{asset}.{level}"
                for permission, dict_val in scope_dict.items()
                for asset, level in dict_val.items()
            ],
        )
