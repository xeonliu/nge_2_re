import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))

from app.parser.tools.common import to_eva_sjis

class TestCommonFunctions(unittest.TestCase):
    def test_to_eva_sjis_valid(self):
        # 测试有效输入
        input_text = "测试"
        print(to_eva_sjis(input_text).hex())  # 打印输出以便调试
        expected_output = b'\xa9\xab\xb2\x76'  # 假设这是正确的编码结果
        self.assertEqual(to_eva_sjis(input_text), expected_output)

    def test_to_eva_sjis_invalid(self):
        # 测试无效输入
        input_text = "𠜎"  # 一个无法编码的字符
        with self.assertRaises(Exception) as context:
            to_eva_sjis(input_text)
        self.assertIn("cannot be converted", str(context.exception))

if __name__ == '__main__':
    unittest.main()