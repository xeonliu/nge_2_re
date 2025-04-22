from tools.evs import FUNCTION_SAY_PARAMS


def get_avatar_and_exp(avatar_param: int, exp_param: int):
    avatar = avatar_param & 0x0FFF
    expression = exp_param & 0x0FFF

    avatar_name = None
    expression_name = None

    for name, data in FUNCTION_SAY_PARAMS.items():
        if data["id"] == avatar:
            avatar_name = name
            for expr_name, expr_id in data["expression"].items():
                if expr_id == expression:
                    expression_name = expr_name
                    break
            break

    return avatar_name, expression_name
