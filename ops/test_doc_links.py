"""Regression fixtures for broken paths and Markdown heading references."""
from pathlib import Path
import tempfile
import unittest

from check_doc_links import anchors, check, links


class LinkTests(unittest.TestCase):
    def check_fixture(self, text, extra=None, untracked=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {'README.md': text, **(extra or {})}
            for path, content in {**files, **(untracked or {})}.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            return check(root, files)

    def test_missing_target_is_not_hidden_by_untracked_file(self):
        errors, count, _ = self.check_fixture('[task](tasks/active/task.md)', untracked={'tasks/active/task.md': '# Task'})
        self.assertEqual(count, 1)
        self.assertEqual(len(errors), 1)
        self.assertIn('missing tracked target', errors[0])

    def test_directory_requires_tracked_descendant(self):
        errors, count, _ = self.check_fixture('[tasks](tasks/) [empty](empty/)', {'tasks/done.md': '# Done'})
        self.assertEqual(count, 2)
        self.assertEqual(len(errors), 1)
        self.assertIn('empty/', errors[0])

    def test_relative_paths_encoded_spaces_and_reference_definition(self):
        errors, count, external = self.check_fixture('[nested](docs/child.md)', {
            'docs/child.md': '[home](../README.md)\n[ref]: <some file.md#the-heading>\n',
            'docs/some file.md': '# The heading\n[encoded](some%20file.md)',
        })
        self.assertEqual((errors, count, external), ([], 4, 0))

    def test_renamed_heading_fails_while_duplicate_suffix_passes(self):
        errors, count, _ = self.check_fixture('# Title\n# Title\n[good](#title-1) [bad](#old-title)')
        self.assertEqual(count, 2)
        self.assertEqual(len(errors), 1)
        self.assertIn('missing heading', errors[0])

    def test_fences_do_not_supply_links_or_anchors(self):
        source = '```md\n# Fake\n[ignore](gone.md)\n```\n~~~\n[ignore](also-gone.md)\n~~~\n# Real'
        self.assertEqual(list(links(source)), [])
        self.assertEqual(anchors(source), {'real'})

    def test_external_links_are_reported_as_excluded(self):
        errors, local, external = self.check_fixture('[remote](https://example.com/no-such-page#unknown)')
        self.assertEqual((errors, local, external), ([], 0, 1))

    def test_punctuation_inline_code_and_explicit_anchor(self):
        self.assertIn('adr-004--bootstrap-selection', anchors('# ADR-004 — `Bootstrap` selection'))
        self.assertIn('stable', anchors('<a id="stable"></a>'))


if __name__ == '__main__':
    unittest.main()
