from unittest import TestCase, skip

from ready.ready import ready


class ReadyTestCase(TestCase):
    def test_brntn(self):
        ready("brntn.me")
