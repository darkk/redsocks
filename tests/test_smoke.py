from subprocess import check_call
import time

import conftest
import pytest

#@pytest.skip # used for debugging
#def test_sleep(net):
#    check_call('sleep 1h'.split())

@pytest.mark.parametrize('tank', conftest.TANKS.keys())
def test_smoke(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80/')
    assert 'Welcome to nginx!' in page
