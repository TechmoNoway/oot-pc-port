"""Normalize a proved source-stage entry for native boundary verification."""
import hashlib,struct
from input_formats import require

def bind_entry_word(stage):
    instruction=stage.get('entry_instruction',{});word=instruction.get('word')
    require(type(word)is int and 0<=word<=0xffffffff and instruction.get('address')==stage.get('entry')and
        instruction.get('module')==stage.get('module')and
        instruction.get('sha256')==hashlib.sha256(struct.pack('<I',word)).hexdigest(),
        'native boundary lacks its original source entry word')
    require('entry_word'not in stage or stage['entry_word']==word,'native boundary entry words disagree')
    return dict(stage,entry_word=word)
