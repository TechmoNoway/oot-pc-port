"""Independent consumer closure/alias boundaries; no original SDK fixtures."""
import hashlib,struct,sys,unittest
from copy import deepcopy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
from system_event_audit import merge_event_consumers,extend_system_events_audit
from input_formats import InputError

def source(name,entry):
    return dict(symbol=name,module='sdk',entry=entry,size=8,body_sha256='ab'*32,
        symbol_metadata={'index':entry},entry_instruction=dict(word=0xd503201f))
def guard(name,entry):
    return dict(source(name,entry),handler_id=31,names=[name],returns_value=False,return_register=None,
        implementation='guard',signature='artificial guard',entry_word=0xd503201f)

class SystemEventAuditTests(unittest.TestCase):
    def test_retains_early_original_producer_and_closes_all_other_aliases(self):
        a=source('early',0x1000);b=source('consumer',0x1100);c=source('consumer_alias',0x1100)
        before=[guard('early',0x1000),guard('other',0x1200)];snapshot=deepcopy(before)
        result=merge_event_consumers(before,[a,b,c],{'early'})
        self.assertEqual(before,snapshot);self.assertEqual(len(result),2)
        self.assertEqual(set(result[0]['names']),{'consumer','consumer_alias'})
        self.assertEqual(result[0]['handler_id'],31)
        self.assertNotIn(0x1000,[r['entry']for r in result])
    def test_typed_conflicts_crossed_aliases_bodies_and_overlaps_reject(self):
        a=source('early',0x1000);b=source('other',0x1100)
        for change in('typed','body','size','alias','missing','overlap'):
            old=[guard('early',0x1000)];census=[deepcopy(a),deepcopy(b)];retained={'early'}
            if change=='typed':old[0]['handler_id']=456
            if change=='body':old[0]['body_sha256']='cd'*32
            if change=='size':old[0]['size']=4
            if change=='alias':census.append(source('unretained_alias',0x1000))
            if change=='missing':retained.add('absent')
            if change=='overlap':old.append(guard('overlap',0x1104))
            with self.subTest(change=change),self.assertRaises(InputError):merge_event_consumers(old,census,retained)
    def test_source_audit_rejects_absent_or_already_enabled_predecessor(self):
        class Linker:
            def report(self):return {'link_complete':True}
        for original in({},dict(objects_runtime=True,display_objects={'declaration':{'flags':1}})):
            with self.assertRaises(InputError):extend_system_events_audit(Linker(),original,None)

if __name__=='__main__':unittest.main()
