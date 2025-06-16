"""
自动标注检查未通过的翻译
"""
# from .download import update_string


# def check_eboot(warn, error):
#     for elem in error:
#         if elem["stage"] != 0:
#             update_string(elem["key"], "", auth_key, stage=0)
#     for elem in warn:
#         if elem["stage"] == 2:
#             continue
#         while True:
#             try:
#                 update_string(elem["key"], elem["info"], auth_key)
#                 break
#             except Exception as e:
#                 print("retry")
#                 print(e)


# def check_evs(encoding_error, paging_error, escape_error):
#     for elem in encoding_error:
#         if elem["stage"] == 2:
#             continue
#         while True:
#             try:
#                 update_string(elem["key"], elem["info"], auth_key, stage=0)
#                 break
#             except Exception as e:
#                 print("retry")
#                 print(e)

#     for elem in paging_error:
#         if elem["stage"] == 2:
#             continue
#         while True:
#             try:
#                 update_string(elem["key"], elem["info"], auth_key)
#                 break
#             except Exception as e:
#                 print("retry")
#                 print(e)

#     for elem in escape_error:
#         update_string(elem["key"], elem["info"], auth_key)