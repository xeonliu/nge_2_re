import json

# Load evs_say_params.json
with open("evs_say_params.json") as f:
    say_params = json.load(f)

def get_avatar_name(id):
    print(id)
    for key, value in say_params.items():
        if value["id"] == id:
            return key
    return None


def get_facial_expression_name(name, id):
    for key, value in say_params[name]["expression"].items():
        if value == id:
            return key
    return None


def generate_crowdin_entry(id, content, context):
    return None


# Process Function 1 Entry
def process_entry(entry):
    params = entry["parameters"]
    avatar: int = params[0]
    facial_expression: int = params[1]
    audio: int = params[2]

    avatar_name = "Default"
    facial_expression_name = "Default"

    if get_avatar_name(avatar) != None:
        avatar_name = get_avatar_name(avatar)
        facial_expression_name = get_facial_expression_name(
            avatar_name, facial_expression
        )
    content = entry["content"]
    contex_str = f"avatar: {avatar_name}, facial_expression: {facial_expression_name}, audio: {audio}"
    print(content, contex_str)


process_entry(
    {
            "function": 1,
            "parameters": [
                70,
                12288,
                26095
            ],
            "content": "本日１２時３０分。▽\n"
        }
)


# Extract Function 1 in EVS JSON Object.
# function 1: say(avatar, facial_expression, audio) "sentence\n\0"

# Put EVS of different scenes into different folders.
