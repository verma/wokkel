# -*- test-case-name: wokkel.test.test_jingle -*-
#
# Copyright (c) Uday Verma
# See LICENSE for details.

"""
XMPP Jingle Protocol.

This protocol is specified in
U{XEP-0166<http://xmpp.org/extensions/xep-0166.html>}.
"""

from zope.interface import implements

from twisted.internet import defer
from twisted.python import log
from twisted.words.protocols.jabber import jid, error
from twisted.words.xish import domish

from wokkel import disco, data_form, generic, shim
from wokkel.compat import IQ
from wokkel.subprotocols import IQHandlerMixin, XMPPHandler

_NS_BASE='urn:xmpp:jingle'

NS_JINGLE = _NS_BASE + ':1'
NS_JINGLE_ERRORS = _NS_BASE + ':errors:1'

NS_JINGLE_APPS_RTP = _NS_BASE + ':apps:rtp:1'
NS_JINGLE_ICE_TRANSPORT = _NS_BASE + ':transports:ice-udp:1'

ACTION_SESSION_INITIATE = 'session-initiate'
ACTION_SESSION_ACCEPT = 'session-accept'
ACTION_SESSION_TERMINATE = 'session-terminate'

# XPath jingle IQ requests
IQ_JINGLE_REQUEST = '/iq[@type="get" or @type="set"]/' + \
                    'jingle[@xmlns="' + NS_JINGLE + '"]'


class Parameter(object):
    """
    A class representing a payload parameter
    """
    def __init__(self, name, value):
        self.name, self.value = name, value

    @staticmethod
    def fromElement(element):
        return Parameter(element.getAttribute('name'),
                element.getAttribute('value'))

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'parameter'))
        element['name'] = self.name
        element['value'] = self.value or ''
        return element


class Crypto(object):
    """
    A crypto method which makes up the encryption to be used
    """
    def __init__(self, crypto_suite, key_params, tag, session_params = None):
        self.crypto_suite, self.key_params, self.tag, self.session_params = \
                crypto_suite, key_params, tag, session_params

    @staticmethod
    def fromElement(element):
        return Crypto(element.getAttribute('crypto-suite'),
                element.getAttribute('key-params'),
                element.getAttribute('tag'),
                element.getAttribute('session-params'))

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'crypto'))
        element['crypto-suite'] = self.crypto_suite
        element['key-params'] = self.key_params
        if self.session_params:
            element['session-params'] = self.session_params
        element['tag'] = self.tag

        return element


class Encryption(object):
    """
    A class representing encryption method
    """
    def __init__(self, required=False, cryptos=[]):
        self.required, self.cryptos = required, cryptos

    @staticmethod
    def fromElement(element):
        cryptos = []
        for child in element.elements():
            cryptos.append(Crypto.fromElement(child))

        required = element.hasAttribute('required') and \
                (element.getAttribute('required').lower() in ['true', '1'])

        return Encryption(required, cryptos)

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'encryption'))
        if self.required:
            element['required'] = '1'

        for c in self.cryptos:
            element.addChild(c.toElement(defaultUri))
        return element


class Bandwidth(object):
    """
    A class representing the bandwidth element
    """
    def __init__(self, typ, value):
        self.typ, self.value = typ, value

    @staticmethod
    def fromElement(element):
        return Bandwidth(element.getAttribute('type'), str(element))

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'bandwidth'))
        element['type'] = self.typ
        element.addContent(self.value)
        return element


class PayloadType(object):
    """
    A class representing payload type
    """
    def __init__(self, id, name, clockrate = 0, channels=0, maxptime=None, ptime=None, parameters=[]):
        self.id, self.name, self.clockrate, self.channels, \
        self.maxptime, self.ptime, self.parameters = \
                id, name, clockrate, channels, maxptime, ptime, parameters

    @staticmethod
    def fromElement(element):
        def _sga(v, t):
            """
            SafeGetAttribute
            """
            try:
                return t(element.getAttribute(v))
            except TypeError:
                pass
            except ValueError:
                pass
            return None


        params = []
        for c in element.children:
            params.append(Parameter.fromElement(c))

        return PayloadType(int(element.getAttribute('id')),
                element.getAttribute('name'),
                _sga('clockrate', int) or 0,
                _sga('channels', int) or 0,
                _sga('maxptime', int) or 0,
                _sga('ptime', int) or 0,
                params)

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri,'payload-type'))

        def _aiv(k, v):
            """
            AppendIfValid
            """
            if v:
                element[k] = str(v)

        element['id'] = str(self.id)

        _aiv('name', self.name)
        _aiv('clockrate', self.clockrate)
        _aiv('channels', self.channels)
        _aiv('maxptime', self.maxptime)
        _aiv('ptime', self.ptime)

        for p in self.parameters:
            element.addChild(p.toElement())

        return element

class ICECandidate(object):
    """
    A class representing a candidate
    """
    def __init__(self, component, foundation, generation,
            id, ip, network, port, priority, protocol, typ,
            related_addr=None, related_port=0):
        self.component, self.foundation, self.generation, \
            self.id, self.ip, self.network, self.port, self.priority, \
            self.protocol, self.typ, self.related_addr, self.related_port = \
                    component, foundation, generation, \
                    id, ip, network, port, priority, protocol, typ, \
                    related_addr, related_port

    @staticmethod
    def fromElement(element):
        def _gas(*names):
            """
            GetAttributeS
            """
            def default_val(t):
                return None if t is str else t()

            return [(t(element.getAttribute(name)) if element.hasAttribute(name) else default_val(t)) for name, t in names]

        return ICECandidate(*_gas(('component', int), ('foundation', int),
            ('generation', int), ('id', str) , ('ip', str),
            ('network', int), ('port', int), ('priority', int), ('protocol', str),
            ('type', str), ('rel-addr', str), ('rel-port', int)))

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'candidate'))
        def _aas(*names):
            """
            AddAttributeS
            """
            for n, v in names:
                if v:
                    element[n] = str(v)

        _aas(*[('component', self.component),
            ('foundation', self.foundation),
            ('generation', self.generation),
            ('id', self.id),
            ('ip', self.ip),
            ('network', self.network),
            ('port', self.port),
            ('priority', self.priority),
            ('protocol', self.protocol),
            ('type', self.typ),
            ('rel-addr', self.related_addr),
            ('rel-port', self.related_port)])
        return element


class RemoteCandidate(object):
    """
    A class represeting a remote candidate entity
    """
    def __init__(self, component, ip, port):
        self.component, self.ip, self.port = \
                component, ip, port

    @staticmethod
    def fromElement(element):
        return RemoteCandidate(int(element.getAttribute('component') or '0'),
                element.getAttribute('ip'),
                int(element.getAttribute('port') or '0'))

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri, 'remote-candidate'))
        element['component'] = str(self.component)
        element['ip'] = self.ip
        element['port'] = str(self.port)

        return element

class ICETransport(object):
    """
    Represents a transport type
    """
    def __init__(self, pwd=None, ufrag=None, candidates=[], remote_candidate=None):
        self.password, self.ufrag, self.candidates, self.remote_candidate = \
                pwd, ufrag, candidates, remote_candidate

    @staticmethod
    def fromElement(element):
        password = element.getAttribute('pwd') or None
        ufrag = element.getAttribute('ufrag') or None

        candidates = []
        remote_candidate = None
        for child in element.elements():
            if child.name == 'remote-candidate' and remote_candidate is None:
                remote_candidate = RemoteCandidate.fromElement(child)
            elif child.name == 'candidate':
                candidates.append(ICECandidate.fromElement(child))

        return ICETransport(pwd=password, ufrag=ufrag, candidates=candidates,
                remote_candidate = remote_candidate)

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri or NS_JINGLE_ICE_TRANSPORT, 'transport'))
        if self.password:
            element['pwd'] = self.password
        if self.ufrag:
            element['ufrag'] = self.ufrag

        if self.remote_candidate:
            element.addChild(self.remote_candidate.toElement())
        elif self.candidates:
            for c in self.candidates:
                element.addChild(c.toElement())

        return element



class RTPDescription(object):
    """
    A class representing a RTP description
    """
    def __init__(self, name=None, media=None, ssrc=None, payloads=[],
            encryption=None, bandwidth=None):
        self.name, self.media, self.ssrc, self.payloads, \
                self.encryption, self.bandwidth = \
                name, media, ssrc, payloads, encryption, bandwidth

    @staticmethod
    def fromElement(element):
        plds = []
        encryption, bandwidth = None, None

        for child in element.elements():
            if child.name == 'payload-type':
                plds.append(PayloadType.fromElement(child))

            if child.name == 'encryption':
                encryption = Encryption.fromElement(child)
            if child.name == 'bandwidth':
                bandwidth = Bandwidth.fromElement(child)


        return RTPDescription(element.getAttribute('name'),
                element.getAttribute('media'), 
                element.getAttribute('ssrc'), plds, encryption,
                bandwidth)

    def toElement(self, defaultUri=None):
        element = domish.Element((defaultUri or NS_JINGLE_APPS_RTP, 'description'))
        if self.name:
            element['name'] = self.name

        if self.media:
            element['media'] = self.media
        for p in self.payloads:
            element.addChild(p.toElement(defaultUri))

        if self.encryption:
            element.addChild(self.encryption.toElement(defaultUri))
        if self.bandwidth:
            element.addChild(self.bandwidth.toElement(defaultUri))

        return element


class Content(object):
    """
    A class indicating a single content item within a jingle request.
    """
    def __init__(self, creator, name, disposition=None, senders=None):
        self.creator, self.name, self.disposition, self.senders = \
                creator, name, disposition, senders

    @staticmethod
    def fromElement(element):
        creator = element.getAttribute('creator')
        name = element.getAttribute('name')
        disposition = element.getAttribute('disposition')
        senders = element.getAttribute('senders')

        description, transport = None, None
        for c in element.elements():
            if c.name == 'description' and c.uri == NS_JINGLE_APPS_RTP:
                description = RTPDescription.fromElement(c)
            elif c.name =='transport' and c.uri == NS_JINGLE_ICE_TRANSPORT:
                transport = ICETransport.fromElement(c)

        ret = Content(creator, name, content, disposition, senders)
        ret.description = description
        ret.transport = transport

    def toElement(self):
        element = domish.Element((None, 'content'))
        element['creator'] = self.creator
        element['name'] = self.name
        if self.disposition:
            element['disposition'] = self.disposition
        if self.senders:
            element['senders'] = self.senders

        for c in self.content:
            element.addChild(c.toElement())

        return element


