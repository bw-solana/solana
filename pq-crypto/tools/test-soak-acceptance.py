#!/usr/bin/env python3
"""Synthetic regressions for experiment acceptance, without hosts or keys."""
import copy
import importlib.util
from pathlib import Path
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


soak = module('soak-cluster')
stage = module('stage-cluster')
PINS = {'executable_sha384':'a'*96,'configuration_sha384':'b'*96,'argv_sha384':'c'*96}


def resources():
    return {'samples':[{'wall_seconds':t,'monotonic_seconds':t+1000,'process':{'pid':123,'start_jiffies':456,
        'cpu_seconds':t/10,'rss_bytes':1048576,'io':{'read_bytes':t*100,'write_bytes':t*200},**PINS},
        'cpu_jiffies':[t]*8,'memory':{'MemAvailable':100000000},'network':{'eth0':{'rx_bytes':t*100}},
        'disk':{'nvme0n1':{'write_bytes':t*100}},'counter_available':{'network':True,'disk':True},'errors':[]}
        for t in range(0,3721,5)]}


def old_resource_accepts(document):
    samples = document['samples']
    observed = sum(b['wall_seconds']-a['wall_seconds'] for a,b in zip(samples,samples[1:])
        if a['process'] and b['process'] and (a['process']['pid'],a['process']['start_jiffies']) == (b['process']['pid'],b['process']['start_jiffies']))
    return samples[0]['wall_seconds']<=60 and samples[-1]['wall_seconds']>=3660 and observed>=3600


def captured_stage():
    return {'genesis_hash':'genesis','source_sha384':'d'*96,'validator_binary_sha384':PINS['executable_sha384'],
        'nodes':[{'node':i,'host':f'host{i}','config_sha384':PINS['configuration_sha384'],
            'executable_sha384':PINS['executable_sha384'],'argv_sha384':PINS['argv_sha384'],
            'rayon_global_threads':8,'parameters':{'execution_threads':8,'proposal_target_block_bytes':8388608},
            'pid':1000+i,'start_jiffies':100+i,'native_status':{'finalized_transactions':1}}for i in range(8)]}


class AcceptanceTests(unittest.TestCase):
    def checked(self, document):
        return soak.resource_traffic_coverage(document,60,3660,PINS)

    def test_normal_five_second_cadence(self):
        result=self.checked(resources())
        self.assertTrue(result['covers_traffic'])
        self.assertTrue(result['owned_process_covers_hour'])
        self.assertEqual(result['maximum_observed_sampling_gap_seconds'],5)

    def test_interior_sixty_second_process_hole_old_false_accept(self):
        doc=resources()
        for s in doc['samples']:
            if 1800<=s['wall_seconds']<=1860:s['process']=None
        self.assertTrue(old_resource_accepts(doc))
        self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_interior_sampler_hole_old_false_accept(self):
        doc=resources();doc['samples']=[s for s in doc['samples']if not 1800<=s['wall_seconds']<=1860]
        self.assertTrue(old_resource_accepts(doc))
        self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_latched_errors_old_false_accept(self):
        doc=resources()
        for s in doc['samples']:
            if s['wall_seconds']>=1800:s['errors']=['proc IO read failure']
        self.assertTrue(old_resource_accepts(doc))
        self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_pid_or_start_identity_change_old_false_accept(self):
        for field in ('pid','start_jiffies'):
            with self.subTest(field=field):
                doc=resources()
                for s in doc['samples']:
                    if s['wall_seconds']>=1800:s['process'][field]+=1
                self.assertTrue(old_resource_accepts(doc))
                self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_changed_process_pins(self):
        for field in PINS:
            with self.subTest(field=field):
                doc=resources();doc['samples'][360]['process'][field]='e'*96
                self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_missing_io_or_host_counter(self):
        for field in ('io','network'):
            with self.subTest(field=field):
                doc=resources()
                if field=='io':doc['samples'][360]['process']['io']=None
                else:doc['samples'][360]['counter_available']['network']=False
                self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_resource_clock_jump(self):
        doc=resources()
        for s in doc['samples']:
            if s['wall_seconds']>=1800:s['wall_seconds']+=60
        self.assertTrue(old_resource_accepts(doc))
        self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_counter_reset(self):
        doc=resources();doc['samples'][360]['process']['io']['read_bytes']=0
        self.assertFalse(self.checked(doc)['covers_traffic'])

    def test_boundary_tolerance_is_explicit_and_bounded(self):
        doc=resources();doc['samples']=[s for s in doc['samples']if not 60<=s['wall_seconds']<=70]
        self.assertFalse(self.checked(doc)['covers_traffic'])
        doc=resources();doc['samples'][11]['process']=None
        self.assertTrue(self.checked(doc)['covers_traffic']) # Waiting wrapper before first admission is outside traffic.

    def test_source_wall_and_monotonic_hour_required(self):
        result={'first_admission_unix_ms':1000,'last_admission_unix_ms':3661000,
            'admission_span_seconds_monotonic':3660,'largest_admission_gap_ms':1000}
        self.assertTrue(soak.continuous_source_spans([result,result])[2])
        bad=dict(result,admission_span_seconds_monotonic=3500)
        self.assertFalse(soak.continuous_source_spans([result,bad])[2])
        self.assertFalse(soak.continuous_source_spans([result,dict(result,largest_admission_gap_ms=30001)])[2])
        self.assertFalse(soak.continuous_source_spans([result,dict(result,admission_span_seconds_monotonic=None)])[2])

    def test_explicit_stage_preservation(self):
        before=captured_stage();after=copy.deepcopy(before)
        after['nodes'][0]['native_status']['finalized_transactions']=999
        self.assertTrue(stage.preserves_operating_point(before,after))
        for field in ('pid','start_jiffies','config_sha384','executable_sha384','argv_sha384','rayon_global_threads','parameters'):
            with self.subTest(field=field):
                changed=copy.deepcopy(after);changed['nodes'][0][field]='changed'
                self.assertFalse(stage.preserves_operating_point(before,changed))
        changed=copy.deepcopy(after);del changed['nodes'][0]['start_jiffies']
        self.assertFalse(stage.preserves_operating_point(before,changed))


if __name__=='__main__':
    unittest.main(verbosity=2)
