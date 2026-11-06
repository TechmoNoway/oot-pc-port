"""Audit policy-6 callee blockers on freshly verified linked inputs; never execute."""

import argparse
import json
from pathlib import Path
import sys

from callee_audit import audit_callees,compare_baseline
from input_formats import require
from link_exefs import load_prepared,build_destination
from module_linker import Linker
from survey_function_profiles import write_report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('exefs',type=Path)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--samples',type=int,default=16)
    parser.add_argument('--max-words',type=int,default=256)
    args=parser.parse_args()
    try:
        destination=build_destination(args.report)
        require(not destination.exists(),'choose a fresh callee audit report path')
        require(not destination.is_relative_to(args.exefs.resolve()),'audit output must be separate from prepared inputs')
        require(0 <= args.samples <= 4096 and 1 <= args.max_words <= 256,'invalid audit limits')
        baseline=None
        if args.baseline:
            require(args.baseline.stat().st_size <= 64*1024*1024,'baseline report exceeds size limit')
            baseline=json.loads(args.baseline.read_text(encoding='utf-8'))
        linker=Linker(load_prepared(args.exefs));linked=linker.apply()
        require(linked['link_complete'],'callee audit requires complete verified offline linking')
        def progress(module,stage,done,total):print(f'{module}: {stage} {done}/{total}',file=sys.stderr,flush=True)
        report=audit_callees(linker.modules,args.samples,args.max_words,progress)
        if baseline is not None:compare_baseline(report,baseline)
        report['offline_link']=linked
        write_report(report,destination)
        print(json.dumps({'report':str(destination),'totals':report['totals'],'guest_code_executed':False}))
        return 0
    except (OSError,ValueError,EOFError) as error:
        print(f'Callee audit failed: {error}',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
