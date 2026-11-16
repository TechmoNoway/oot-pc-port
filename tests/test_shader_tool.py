"""Synthetic external protocol, result binding and fail-closed parsing tests."""
import json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from input_formats import InputError
from shader_tool import HEADER,ROOT,adapter_identity,digest,encode_request,inspect_spirv,translate

def module(stage=5):
    return struct.pack('<13I',0x07230203,0x10000,0,2,0,(2<<16)|17,1,(6<<16)|15,stage,1,0x6e69616d,0,0)

class ShaderToolTests(unittest.TestCase):
    def test_captured_protocol_queries_have_no_implicit_answers(self):
        code=struct.pack('<4I',0x794d,0,0,0)
        data=encode_request(code,stage=2,workgroup=(1,1,1),constants=[(3,4,0x12345678)],textures=[(7,2,0,0)])
        self.assertEqual(HEADER.unpack_from(data)[3:7],(2,16,1,1))
        self.assertEqual(data[80:92],struct.pack('<3I',3,4,0x12345678))
        self.assertEqual(data[-16:],code)
        for change in(dict(stage=3),dict(workgroup=(0,1,1)),dict(workgroup=(1024,2,1)),
            dict(constants=[(3,2,1)]),dict(constants=[(0,0,1),(0,0,2)]),
            dict(textures=[(1,9,0,0)]),dict(textures=[(1,0,102,0)]),dict(texture_bank=32),dict(spirv_version=0x10001),
            dict(ssbo_alignment=3),dict(descriptor_limit=65537)):
            kwargs=dict(stage=2,workgroup=(1,1,1));kwargs.update(change)
            with self.subTest(change=change),self.assertRaises(InputError):encode_request(code,**kwargs)
        with self.assertRaises(InputError):encode_request(bytes(128),stage=0)
    def test_spirv_structure_stage_and_instruction_bounds(self):
        self.assertEqual(inspect_spirv(module(),2)['validation'],'structural-only')
        for data,stage in((module(),0),(b'',2),(module()[:-1],2),
            (module()[:20]+bytes(4),2),(module()[:20]+struct.pack('<I',0xffff0001),2)):
            with self.subTest(data=data,stage=stage),self.assertRaises(InputError):inspect_spirv(data,stage)
    def test_tool_binary_source_and_fresh_output_identity(self):
        parent=ROOT/'build/shader-tool-tests';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent)as folder:
            root=Path(folder);tool=root/'tool.exe';tool.write_bytes(b'synthetic executable')
            receipt=root/'identity.json';identity=dict(schema=1,adapter=adapter_identity(),binary_sha256=digest(tool.read_bytes()))
            receipt.write_text(json.dumps(identity));request=encode_request(bytes(16),stage=2,workgroup=(1,1,1))
            def run(command,**kwargs):
                self.assertNotIn('RX_VK_MESH_FIRST',kwargs['env'])
                Path(command[2]).write_bytes(module());Path(command[3]).write_text(json.dumps(dict(schema=1,stage=2,words=13)))
                class Result:returncode=0;stdout=b'output';stderr=b''
                return Result()
            with patch('shader_tool.subprocess.run',side_effect=run),patch.dict('os.environ',{'RX_VK_MESH_FIRST':'1'}):
                result=translate(tool,receipt,request,root/'job')
                self.assertEqual(result['request_sha256'],digest(request));self.assertFalse(result['game_frame_proven'])
                with self.assertRaises(InputError):translate(tool,receipt,request,root/'job')
                tool.write_bytes(b'changed')
                with self.assertRaises(InputError):translate(tool,receipt,request,root/'changed')
            self.assertFalse((root/'changed').exists())

if __name__=='__main__':unittest.main()
