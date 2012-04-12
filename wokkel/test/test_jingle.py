# Copyright (c) Uday Verma
# See LICENSE for details.

"""
Tests for L{wokkel.jingle}
"""

from zope.interface import verify

from twisted.trial import unittest
from twisted.internet import defer
from twisted.words.xish import domish
from twisted.words.protocols.jabber import error
from twisted.words.protocols.jabber.jid import JID
from twisted.words.protocols.jabber.xmlstream import toResponse

from wokkel import data_form, disco, iwokkel, pubsub, shim, jingle
from wokkel.generic import parseXml
from wokkel.test.helpers import TestableRequestHandlerMixin, XmlStreamStub

_NS_BASE='urn:xmpp:jingle'

NS_JINGLE = _NS_BASE + ':1'
NS_JINGLE_ERRORS = _NS_BASE + ':errors:1'

NS_JINGLE_APPS_RTP = _NS_BASE + ':apps:rtp:1'


def calledAsync(fn):
    """
    Function wrapper that fires a deferred upon calling the given function.
    """
    d = defer.Deferred()

    def func(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
        except:
            d.errback()
        else:
            d.callback(result)

    return d, func


class ParameterTest(unittest.TestCase):
    """
    Test for L{jingle.Parameter}
    """
    def test_fromElement(self):
        xml = """
        <parameter name='delivery-method' value='inline'/>
        """
        p = jingle.Parameter.fromElement(parseXml(xml))
        self.assertEqual('delivery-method', p.name)
        self.assertEqual('inline', p.value)

    def test_fromElementEmptyValue(self):
        xml = """
        <parameter name='delivery-method' value=''/>
        """
        p = jingle.Parameter.fromElement(parseXml(xml))
        self.assertEqual('delivery-method', p.name)
        self.assertEqual('', p.value)

    def test_toElement(self):
        p = jingle.Parameter('hello', 'world')

        element = p.toElement()

        self.assertEqual('hello', element.getAttribute('name'))
        self.assertEqual('world', element.getAttribute('value'))

    def test_toElementNoValue(self):
        p = jingle.Parameter('hello', None)

        element = p.toElement()

        self.assertEqual('hello', element.getAttribute('name'))
        self.assertEqual('', element.getAttribute('value'))


class CryptoTest(unittest.TestCase):
    """
    Tests for L{jingle.Crypto}.
    """
    def test_fromElement(self):
        xml = """
        <crypto
          crypto-suite='AES_CM_128_HMAC_SHA1_80'
          key-params='inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:32'
          session-params='KDR=1 UNENCRYPTED_SRTCP' tag='1'/>
          """

        crypto = jingle.Crypto.fromElement(parseXml(xml))

        self.assertEqual('AES_CM_128_HMAC_SHA1_80', crypto.crypto_suite)
        self.assertEqual('inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:32', crypto.key_params)
        self.assertEqual('KDR=1 UNENCRYPTED_SRTCP', crypto.session_params)
        self.assertEqual('1', crypto.tag)

    def test_fromElementNoSession(self):
        xml = """
        <crypto
          crypto-suite='AES_CM_128_HMAC_SHA1_80'
          key-params='inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:32'
          tag='1'/>
          """

        crypto = jingle.Crypto.fromElement(parseXml(xml))

        self.assertEqual(None, crypto.session_params)

    def test_toElement(self):
        crypto = jingle.Crypto('1', '2', '3')

        element = crypto.toElement()
        self.assertEqual('1', element.getAttribute('crypto-suite'))
        self.assertEqual('2', element.getAttribute('key-params'))
        self.assertEqual('3', element.getAttribute('tag'))
        self.assertEqual(None, element.getAttribute('session-params'))

    def test_toElement(self):
        crypto = jingle.Crypto('1', '2', '3', '4')

        element = crypto.toElement()
        self.assertEqual('1', element.getAttribute('crypto-suite'))
        self.assertEqual('2', element.getAttribute('key-params'))
        self.assertEqual('3', element.getAttribute('tag'))
        self.assertEqual('4', element.getAttribute('session-params'))

class EncryptionTest(unittest.TestCase):
    """
    Tests for L{jingle.EncryptionTest}.
    """
    def test_fromElement(self):
        xml = """
        <encryption required='1' />
        """

        e = jingle.Encryption.fromElement(parseXml(xml))

        self.assertEqual(True, e.required)
        self.assertEqual(0, len(e.cryptos))

    def test_fromElementRequiredTrue(self):
        xml = """
        <encryption required='true'/>
        """

        e = jingle.Encryption.fromElement(parseXml(xml))

        self.assertEqual(True, e.required)

    def test_fromElementNoRequired(self):
        xml = """
        <encryption />
        """

        e = jingle.Encryption.fromElement(parseXml(xml))

        self.assertEqual(False, e.required)

    def test_fromElementExplicitRequiredFalse(self):
        xml = """
        <encryption required='false'/>
        """

        e = jingle.Encryption.fromElement(parseXml(xml))

        self.assertEqual(False, e.required)

    def test_fromElementExplicitRequired0(self):
        xml = """
        <encryption required='0'/>
        """

        e = jingle.Encryption.fromElement(parseXml(xml))

        self.assertEqual(False, e.required)

    def test_fromElementWithCryptos(self):
        xml = """
        <encryption required='1'>
          <crypto
              crypto-suite='AES_CM_128_HMAC_SHA1_80'
              key-params='inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:32'
              session-params='KDR=1 UNENCRYPTED_SRTCP'
              tag='1'/>
        </encryption>
        """

        e = jingle.Encryption.fromElement(parseXml(xml))
        self.assertEqual(1, len(e.cryptos))

    def test_toElementEmpty(self):
        e = jingle.Encryption()

        element = e.toElement()

        self.assertEqual(False, element.hasAttribute('required'))
        self.assertEqual(0, len(element.children))

    def test_toElementRequired(self):
        e = jingle.Encryption(required=True)

        element = e.toElement()

        self.assertEqual('1', element.getAttribute('required'))

    def test_toElementCrypto(self):
        cryptos = [jingle.Crypto('1', '2', '3', '4'), jingle.Crypto('5', '6', '7', '8')]
        e = jingle.Encryption(cryptos=cryptos)

        element = e.toElement()

        self.assertEqual(2, len(element.children))
        self.assertEqual(True, all([c.name == 'crypto' for c in element.children]))

class BandwidthTest(unittest.TestCase):
    """
    Tests for L{jingle.BandwidthTest}.
    """
    def test_fromElement(self):
        xml = """
        <bandwidth type='AS'>128</bandwidth>
        """

        bw = jingle.Bandwidth.fromElement(parseXml(xml))

        self.assertEqual('AS', bw.typ)

    def test_toElement(self):
        element = jingle.Bandwidth('int', '256').toElement()

        self.assertEqual('int', element.getAttribute('type'))
        self.assertEqual('256', str(element))


class PayloadTypeTest(unittest.TestCase):
    """
    Tests for L{jingle.PayloadType}.
    """
    def test_fromElement(self):
        """
        fromElement parses a payload-type from XML DOM.
        """
        xml = """
        <payload-type id='96' name='speex' clockrate='8000'/>
        """
        payload = jingle.PayloadType.fromElement(parseXml(xml))
        self.assertEqual(96, payload.id)
        self.assertEqual('speex', payload.name)
        self.assertEqual(8000, payload.clockrate)
        self.assertEqual(0, payload.maxptime)
        self.assertEqual(0, payload.ptime)
        self.assertEqual(0, payload.channels)
        self.assertEqual([], payload.parameters)


    def test_fromElementNoClockrate(self):
        """
        If no clock-rate is specified, it needs to be handled
        """
        xml = """
        <payload-type id='96' name='speex' />
        """
        payload = jingle.PayloadType.fromElement(parseXml(xml))
        self.assertEqual(0, payload.clockrate)

    def test_fromElementChannelsAndPTimes(self):
        """
        fromElement parses a payload-type from XML DOM.
        """
        xml = """
        <payload-type id='96' name='speex' clockrate='8000' channels='2' ptime='10000' maxptime='1000000' />
        """
        payload = jingle.PayloadType.fromElement(parseXml(xml))
        self.assertEqual(96, payload.id)
        self.assertEqual('speex', payload.name)
        self.assertEqual(8000, payload.clockrate)
        self.assertEqual(2, payload.channels)
        self.assertEqual(10000, payload.ptime)
        self.assertEqual(1000000, payload.maxptime)

    def test_fromElementParams(self):
        """
        fromElement parses a payload-type from XML DOM.
        """
        xml = """
        <payload-type id='96' name='speex' clockrate='8000' channels='2' ptime='10000' maxptime='1000000'>
            <parameter name='encoding' value='fast'/>
            <parameter name='decoding' value='slow'/>
        </payload-type>
        """
        payload = jingle.PayloadType.fromElement(parseXml(xml))
        self.assertEqual(2, len(payload.parameters))


    def test_toElement(self):
        """
        Rendering a PayloadType should yield the proper attributes.
        """
        payload = jingle.PayloadType(96, 'speex', 8000)

        element = payload.toElement()
        self.assertEqual('payload-type', element.name)
        self.assertEqual(None, element.uri)
        self.assertEqual('96', element.getAttribute('id'))
        self.assertEqual('speex', element.getAttribute('name'))
        self.assertEqual('8000', element.getAttribute('clockrate'))


    def test_toElementNoClockRate(self):
        """
        The empty node identifier should not yield a node attribute.
        """
        payload = jingle.PayloadType(96, 'speex')

        element = payload.toElement()
        self.assertFalse(element.hasAttribute('clockrate'))

    def test_toElementAll(self):
        """
        The empty node identifier should not yield a node attribute.
        """
        params = [jingle.Parameter('test1', 'test'), jingle.Parameter('test2', 'test')]
        payload = jingle.PayloadType(96, 'speex', 8000, 2, 10000, 1000, params)

        element = payload.toElement()
        self.assertEqual('2', element.getAttribute('channels'))
        self.assertEqual('1000', element.getAttribute('ptime'))
        self.assertEqual('10000', element.getAttribute('maxptime'))
        self.assertEqual(2, len(element.children))

class RTPDescriptionTest(unittest.TestCase):
    """
    Tests for L{jingle.RTPDescription}.
    """
    def test_fromElementRTP(self):
        xml = """
            <description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>
            <payload-type id='96' name='speex' clockrate='16000'/>
            <payload-type id='97' name='speex' clockrate='8000'/>
            <payload-type id='18' name='G729'/>
            <payload-type id='0' name='PCMU' />
            <payload-type id='103' name='L16' clockrate='16000' channels='2'/>
            <payload-type id='98' name='x-ISAC' clockrate='8000'/>
          </description>"""


        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertEqual('audio', desc.media)
        self.assertEqual(None, desc.name)
        self.assertEqual(None, desc.ssrc)
        self.assertEqual(6, len(desc.payloads))
        self.assertEqual(None, desc.encryption)
        self.assertEqual(None, desc.bandwidth)

    def test_fromElementUnsupported(self):
        xml = """
        <description xmlns='urn:xmpp:jingle:apps:stub:0'/>
        """

        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertEqual(None, desc.media)
        self.assertEqual(None, desc.name)
        self.assertEqual(None, desc.ssrc)
        self.assertEqual([], desc.payloads)
        self.assertEqual(None, desc.encryption)
        self.assertEqual(None, desc.bandwidth)

    def test_fromElementWithName(self):
        xml = """
            <description xmlns='urn:xmpp:jingle:apps:rtp:1' name='test-name' media='audio'>
            <payload-type id='96' name='speex' clockrate='16000'/>
            <payload-type id='98' name='x-ISAC' clockrate='8000'/>
          </description>"""

        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertEqual('test-name', desc.name)

    def test_fromElementWithSSRC(self):
        xml = """
            <description xmlns='urn:xmpp:jingle:apps:rtp:1' name='test-name' media='audio' ssrc='11223344'>
            <payload-type id='96' name='speex' clockrate='16000'/>
            <payload-type id='98' name='x-ISAC' clockrate='8000'/>
          </description>"""
        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertEqual('11223344', desc.ssrc)

    def test_fromElementWithEncryption(self):
        xml = """
            <description xmlns='urn:xmpp:jingle:apps:rtp:1' name='test-name' media='audio' ssrc='11223344'>
            <payload-type id='96' name='speex' clockrate='16000'/>
            <payload-type id='98' name='x-ISAC' clockrate='8000'/>
            <encryption required='1'>
              <crypto
                  crypto-suite='AES_CM_128_HMAC_SHA1_80'
                  key-params='inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:32'
                  session-params='KDR=1 UNENCRYPTED_SRTCP'
                  tag='1'/>
            </encryption>
          </description>"""
        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertNotEqual(None, desc.encryption)
        self.assertEqual(2, len(desc.payloads))

    def test_fromElementWithBandwidth(self):
        xml = """
            <description xmlns='urn:xmpp:jingle:apps:rtp:1' name='test-name' media='audio' ssrc='11223344'>
            <payload-type id='96' name='speex' clockrate='16000'/>
            <payload-type id='98' name='x-ISAC' clockrate='8000'/>
            <bandwidth type='AS' />
          </description>"""
        desc = jingle.RTPDescription.fromElement(parseXml(xml))
        self.assertNotEqual(None, desc.bandwidth)
        self.assertEqual(2, len(desc.payloads))

    def test_toElementRTP(self):
        payloads = [jingle.PayloadType(96, 'speex', 8000), jingle.PayloadType(97, 'speex')]
        desc = jingle.RTPDescription(name='test-name', 
                media='audio', payloads=payloads)

        element = desc.toElement()
        self.assertEqual(element.uri, 'urn:xmpp:jingle:apps:rtp:1')
        self.assertEqual('test-name', element.getAttribute('name'))
        self.assertEqual('audio', element.getAttribute('media'))
        self.assertEqual(2, len(element.children))

    def test_toElementRTPNoName(self):
        payloads = [jingle.PayloadType(96, 'speex', 8000), jingle.PayloadType(97, 'speex')]
        desc = jingle.RTPDescription(media='audio', payloads=payloads)

        element = desc.toElement()
        self.assertEqual(False, element.hasAttribute('name'))

    def test_toElementRTPNoParams(self):
        desc = jingle.RTPDescription()

        element = desc.toElement()
        self.assertEqual(element.uri, jingle.NS_JINGLE_APPS_RTP)
        self.assertEqual(False, element.hasAttribute('name'))
        self.assertEqual(False, element.hasAttribute('media'))
        self.assertEqual(0, len(element.children))

    def test_toElementWithCrypto(self):
        payloads = [jingle.PayloadType(96, 'speex', 8000), jingle.PayloadType(97, 'speex')]
        cryptos = [jingle.Crypto('1', '2', '3', '4'), jingle.Crypto('5', '6', '7', '8')]

        desc = jingle.RTPDescription(media='audio',
                payloads=payloads, encryption=jingle.Encryption(cryptos=cryptos))

        element = desc.toElement()

        self.assertEqual(3, len(element.children))
        self.assertEqual(True, any([c.name == 'encryption' for c in element.elements()]))

    def test_toElementWithBandwidth(self):
        payloads = [jingle.PayloadType(96, 'speex', 8000), jingle.PayloadType(97, 'speex')]

        desc = jingle.RTPDescription(media='audio',
                payloads=payloads, bandwidth=jingle.Bandwidth('AS', '128'))

        element = desc.toElement()

        self.assertEqual(3, len(element.children))
        self.assertEqual(True, any([c.name == 'bandwidth' for c in element.elements()]))

class ICECandidateTest(unittest.TestCase):
    """
    Tests for L{jingle.Candidate}.
    """
    def test_fromElement(self):
        xml = """
            <candidate component='1'
            foundation='2'
            generation='0'
            id='el0747fg11'
            ip='10.0.1.1'
            network='4'
            port='8998'
            priority='2130706431'
            protocol='udp'
            type='host'/>
        """

        candidate = jingle.ICECandidate.fromElement(parseXml(xml))

        self.assertEqual(1, candidate.component)
        self.assertEqual(2, candidate.foundation)
        self.assertEqual(0, candidate.generation)
        self.assertEqual('el0747fg11', candidate.id)
        self.assertEqual('10.0.1.1', candidate.ip)
        self.assertEqual(4, candidate.network)
        self.assertEqual(8998, candidate.port)
        self.assertEqual(2130706431, candidate.priority)
        self.assertEqual('udp', candidate.protocol)
        self.assertEqual('host', candidate.typ)
        self.assertEqual(None, candidate.related_addr)
        self.assertEqual(0, candidate.related_port)

    def test_fromElementRelFields(self):
        xml = """
            <candidate component='1'
            foundation='2'
            generation='0'
            id='el0747fg11'
            ip='10.0.1.1'
            network='4'
            port='8998'
            priority='2130706431'
            protocol='udp'
            rel-addr='rel-addr-test'
            rel-port='9899'
            type='host'/>
        """

        candidate = jingle.ICECandidate.fromElement(parseXml(xml))

        self.assertEqual(1, candidate.component)
        self.assertEqual(2, candidate.foundation)
        self.assertEqual(0, candidate.generation)
        self.assertEqual('el0747fg11', candidate.id)
        self.assertEqual('10.0.1.1', candidate.ip)
        self.assertEqual(4, candidate.network)
        self.assertEqual(8998, candidate.port)
        self.assertEqual(2130706431, candidate.priority)
        self.assertEqual('udp', candidate.protocol)
        self.assertEqual('host', candidate.typ)
        self.assertEqual('rel-addr-test', candidate.related_addr)
        self.assertEqual(9899, candidate.related_port)

    def test_toElement(self):
        c = jingle.ICECandidate(1, 2, 3, 'id123',
                '10.0.0.1', 4, 9191, 123456, 'udp', 'host')

        element = c.toElement()

        self.assertEqual('1', element.getAttribute('component'))
        self.assertEqual('2', element.getAttribute('foundation'))
        self.assertEqual('3', element.getAttribute('generation'))
        self.assertEqual('id123', element.getAttribute('id'))
        self.assertEqual('10.0.0.1', element.getAttribute('ip'))
        self.assertEqual('4', element.getAttribute('network'))
        self.assertEqual('9191', element.getAttribute('port'))
        self.assertEqual('123456', element.getAttribute('priority'))
        self.assertEqual('udp', element.getAttribute('protocol'))
        self.assertEqual('host', element.getAttribute('type'))
        self.assertEqual(None, element.getAttribute('rel-addr'))
        self.assertEqual(None, element.getAttribute('rel-port'))

    def test_toElementWithRelated(self):
        c = jingle.ICECandidate(1, 2, 3, 'id123',
                '10.0.0.1', 4, 9191, 123456, 'udp', 'host',
                'related-test-server', '5454')

        element = c.toElement()

        self.assertEqual('1', element.getAttribute('component'))
        self.assertEqual('2', element.getAttribute('foundation'))
        self.assertEqual('3', element.getAttribute('generation'))
        self.assertEqual('id123', element.getAttribute('id'))
        self.assertEqual('10.0.0.1', element.getAttribute('ip'))
        self.assertEqual('4', element.getAttribute('network'))
        self.assertEqual('9191', element.getAttribute('port'))
        self.assertEqual('123456', element.getAttribute('priority'))
        self.assertEqual('udp', element.getAttribute('protocol'))
        self.assertEqual('host', element.getAttribute('type'))
        self.assertEqual('related-test-server', element.getAttribute('rel-addr'))
        self.assertEqual('5454', element.getAttribute('rel-port'))


class RemoteCandidateTest(unittest.TestCase):
    """
    Test cases for L{jingle.RemoteCandidate}
    """
    def test_fromElement(self):
        xml = """
        <remote-candidate component='1'
                         ip='10.0.1.2'
                         port='9001'/>
                         """

        r = jingle.RemoteCandidate.fromElement(parseXml(xml))
        self.assertEqual(r.component, 1)
        self.assertEqual(r.ip, '10.0.1.2')
        self.assertEqual(r.port, 9001)

    def test_toElement(self):
        r = jingle.RemoteCandidate(1, '1.2.3.4', 5050)

        element = r.toElement()
        self.assertEqual(element['component'], '1')
        self.assertEqual(element['ip'], '1.2.3.4')
        self.assertEqual(element['port'], '5050')


class ICETransportTest(unittest.TestCase):
    """
    Test cases for L{jingle.ICETransport}
    """
    def test_fromElementCandidates(self):
        xml = """
        <transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'
                 pwd='asd88fgpdd777uzjYhagZg'
                 ufrag='8hhy'>
        <candidate component='1'
                   foundation='1'
                   generation='0'
                   id='el0747fg11'
                   ip='10.0.1.1'
                   network='1'
                   port='8998'
                   priority='2130706431'
                   protocol='udp'
                   type='host'/>
        <candidate component='1'
                   foundation='2'
                   generation='0'
                   id='y3s2b30v3r'
                   ip='192.0.2.3'
                   network='1'
                   port='45664'
                   priority='1694498815'
                   protocol='udp'
                   rel-addr='10.0.1.1'
                   rel-port='8998'
                   type='srflx'/>
        </transport>
        """

        transport = jingle.ICETransport.fromElement(parseXml(xml))

        self.assertEqual(transport.password, 'asd88fgpdd777uzjYhagZg')
        self.assertEqual(transport.ufrag, '8hhy')
        self.assertEqual(transport.remote_candidate, None)
        self.assertEqual(len(transport.candidates), 2)

        self.assertEqual(transport.candidates[0].component, 1)
        self.assertEqual(transport.candidates[0].foundation, 1)
        self.assertEqual(transport.candidates[0].generation, 0)
        self.assertEqual(transport.candidates[0].id, 'el0747fg11')
        self.assertEqual(transport.candidates[0].ip, '10.0.1.1')
        self.assertEqual(transport.candidates[0].port, 8998)
        self.assertEqual(transport.candidates[0].network, 1)
        self.assertEqual(transport.candidates[0].priority, 2130706431)
        self.assertEqual(transport.candidates[0].protocol, 'udp')
        self.assertEqual(transport.candidates[0].typ, 'host')
        self.assertEqual(transport.candidates[0].related_addr, None)
        self.assertEqual(transport.candidates[0].related_port, 0)

        self.assertEqual(transport.candidates[1].component, 1)
        self.assertEqual(transport.candidates[1].foundation, 2)
        self.assertEqual(transport.candidates[1].generation, 0)
        self.assertEqual(transport.candidates[1].id, 'y3s2b30v3r')
        self.assertEqual(transport.candidates[1].ip, '192.0.2.3')
        self.assertEqual(transport.candidates[1].port, 45664)
        self.assertEqual(transport.candidates[1].network, 1)
        self.assertEqual(transport.candidates[1].priority, 1694498815)
        self.assertEqual(transport.candidates[1].protocol, 'udp')
        self.assertEqual(transport.candidates[1].typ, 'srflx')
        self.assertEqual(transport.candidates[1].related_addr, '10.0.1.1')
        self.assertEqual(transport.candidates[1].related_port, 8998)

    def test_fromElementRemoteCandidate(self):
        xml = """
        <transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'
                pwd='asd88fgpdd777uzjYhagZg'
                ufrag='8hhy'>
        <remote-candidate component='1'
                         ip='10.0.1.2'
                         port='9001'/>
                         </transport>
        """

        transport = jingle.ICETransport.fromElement(parseXml(xml))

        self.assertEqual(transport.password, 'asd88fgpdd777uzjYhagZg')
        self.assertEqual(transport.ufrag, '8hhy')
        self.assertNotEqual(transport.remote_candidate, None)
        self.assertEqual(transport.candidates, [])

        self.assertEqual(transport.remote_candidate.component, 1)
        self.assertEqual(transport.remote_candidate.ip, '10.0.1.2')
        self.assertEqual(transport.remote_candidate.port, 9001)

    def test_toElementCandidates(self):
        candidates = [jingle.ICECandidate(1, 1, 3, 'id123',
                '10.0.0.1', 4, 9191, 123456, 'udp', 'host'),
                jingle.ICECandidate(1, 2, 3, 'id456',
                    '10.0.0.1', 4, 9191, 123456, 'udp', 'host',
                    'related-test-server', '5454')]

        transport = jingle.ICETransport(pwd='1234', ufrag='546', 
                candidates=candidates)

        element = transport.toElement()

        self.assertEqual(element.uri, 'urn:xmpp:jingle:transports:ice-udp:1')
        self.assertEqual(element.name, 'transport')

        self.assertEqual(element['pwd'], '1234')
        self.assertEqual(element['ufrag'], '546')
        self.assertEqual(len(element.children), 2)
        for c in element.children:
            self.assertEqual('candidate', c.name)

        self.assertEqual(element.children[0]['id'], 'id123')
        self.assertEqual(element.children[1]['id'], 'id456')
        self.assertEqual(element.children[0].getAttribute('rel-addr'), None)
        self.assertEqual(element.children[1].getAttribute('rel-addr'), 'related-test-server')

    def test_toElementRemoteCandidate(self):
        transport = jingle.ICETransport(pwd='123', ufrag='456',
                remote_candidate = jingle.RemoteCandidate(1, '10.0.0.123', 8989))

        element = transport.toElement()

        self.assertEqual(element.uri, 'urn:xmpp:jingle:transports:ice-udp:1')
        self.assertEqual(element.name, 'transport')

        self.assertEqual(element['pwd'], '123')
        self.assertEqual(element['ufrag'], '456')
        self.assertEqual(len(element.children), 1)

        self.assertEqual(element.children[0].name, 'remote-candidate')
        self.assertEqual(element.children[0]['component'], '1')
        self.assertEqual(element.children[0]['ip'], '10.0.0.123')
        self.assertEqual(element.children[0]['port'], '8989')

