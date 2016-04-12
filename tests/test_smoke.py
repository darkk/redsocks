from functools import partial
from subprocess import check_call
import time

import conftest
import pytest

@pytest.mark.skipif(not pytest.config.getoption('--vmdebug'), reason='need --vmdebug option to run')
def test_vmdebug(net):
    check_call('sleep 365d'.split())

@pytest.mark.parametrize('tank', conftest.TANKS.keys())
def test_smoke(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80/')
    assert 'Welcome to nginx!' in page

RTT = 200 # ms

@pytest.fixture(scope="function")
def slow_net(request, net):
    def close():
        net.vm['gw'].netcall('tc qdisc del dev ethx root')
        net.vm['gw'].netcall('tc qdisc del dev ethw root')
    request.addfinalizer(close)
    net.vm['gw'].netcall('tc qdisc add dev ethw root netem delay %dms' % (RTT / 2))
    net.vm['gw'].netcall('tc qdisc add dev ethx root netem delay %dms' % (RTT / 2))
    return net

LATENCY = {
    'connect_none':     3 * RTT,
    'connect_basic':    3 * RTT,
    'connect_digest':   3 * RTT,
    'socks5_none':      4 * RTT,
    'socks5_auth':      5 * RTT,
    'regw_direct':      2 * RTT,
}

def heatup(vm):
    vm.do('curl -o /dev/null http://10.0.1.80/') # heatup L2 and auth caches

def http_ping(vm):
    s = vm.do('curl -sS -w %{{time_connect}}/%{{time_total}}/%{{http_code}}/%{{size_download}} -o /dev/null http://10.0.1.80/')
    connect, total, code, size = s.split('/')
    connect, total, code, size = float(connect) * 1000, float(total) * 1000, int(code), int(size)
    return connect, total, code, size

@pytest.mark.parametrize('tank', conftest.TANKS.keys())
def test_latency_tank(slow_net, tank):
    vm = slow_net.vm['tank%d' % conftest.TANKS[tank]]
    heatup(vm)
    connect, total, code, size = http_ping(vm)
    assert code == 200 and size == 612
    assert connect < 0.005 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2

def test_latency_regw(slow_net):
    vm, tank = slow_net.vm['regw'], 'regw_direct'
    heatup(vm)
    connect, total, code, size = http_ping(vm)
    assert code == 200 and size == 612
    assert RTT*.8 < connect and connect < RTT*1.2 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2

def test_nonce_reuse(slow_net):
    """ nonce reuse works and has no latency penalty """
    tank = 'connect_digest'
    vm = slow_net.vm['tank%d' % conftest.TANKS[tank]]
    heatup(vm)
    begin = time.time()
    s = conftest.pmap([partial(http_ping, vm) for _ in range(5)])
    total_sum = time.time() - begin
    for connect, total, code, size in s:
        assert code == 200 and size == 612
        assert connect < 0.005 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2
        assert total_sum < total * 1.5
