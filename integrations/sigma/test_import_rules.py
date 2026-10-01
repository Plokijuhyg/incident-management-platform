import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import import_rules as imp

BASE='''title: Fixture
id: 10000000-0000-4000-8000-000000000001
level: high
tags: [attack.defense-evasion, attack.t1070.001]
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    TargetUserName|contains: admin
  condition: selection
'''
class ImportTests(unittest.TestCase):
    def prepare(self,text):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'rule.yml').write_text(text)
            return imp.prepare(p)
    def test_official_parser_compiles_and_preserves_tags_and_source(self):
        row=self.prepare(BASE)[0];d=json.loads(row[4])
        self.assertEqual('High',row[2]);self.assertEqual('attack.defense-evasion',row[3])
        self.assertEqual('Compiled',d['status']);self.assertEqual(64,len(d['sourceSha256']))
        self.assertEqual(['attack.defense-evasion','attack.t1070.001'],d['tags'])
    def test_levels_are_explicit_unknown_aborts(self):
        for level,mapped in imp.LEVELS.items():self.assertEqual(mapped,self.prepare(BASE.replace('level: high','level: '+level))[0][2])
        with self.assertRaises(ValueError):self.prepare(BASE.replace('level: high','level: severe'))
    def test_invalid_condition_retained_as_unsupported(self):
        d=json.loads(self.prepare(BASE.replace('condition: selection','condition: missing_selection'))[0][4])
        self.assertEqual('Unsupported',d['status']);self.assertIsNone(d['compiled'])
    def test_duplicate_ids_abort_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'a.yml').write_text(BASE);(p/'b.yml').write_text(BASE)
            with self.assertRaises(ValueError):imp.prepare(p)
    def test_yaml_cannot_construct_python_objects(self):
        with self.assertRaises(Exception):self.prepare('!!python/object/apply:os.system [echo unsafe]')
    def test_deterministic_definition_for_rerun(self):self.assertEqual(self.prepare(BASE),self.prepare(BASE))

if __name__=='__main__': unittest.main()
