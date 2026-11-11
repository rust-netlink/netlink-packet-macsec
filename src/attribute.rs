// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, EncodeError, EncodeErrorKind,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, append_bytes,
    append_u32, append_u32_be, append_u64, append_u64_be, parse_u8, parse_u16,
    parse_u32, parse_u32_be, parse_u64, parse_u64_be,
};

pub(crate) fn parse_attributes<T>(buf: &[u8]) -> Result<Vec<T>, DecodeError>
where
    T: for<'a> Parseable<NlaBuffer<'a>>,
{
    let mut attributes = Vec::new();
    for nla in NlasIterator::new(buf)? {
        attributes.push(
            T::parse(&nla)
                .context("failed to parse macsec netlink attributes")?,
        );
    }
    Ok(attributes)
}

const MACSEC_CIPHER_ID_GCM_AES_128: u64 = 0x0080C20001000001;
const MACSEC_CIPHER_ID_GCM_AES_256: u64 = 0x0080C20001000002;
const MACSEC_CIPHER_ID_GCM_AES_XPN_128: u64 = 0x0080C20001000003;
const MACSEC_CIPHER_ID_GCM_AES_XPN_256: u64 = 0x0080C20001000004;
const MACSEC_DEFAULT_CIPHER_ID: u64 = 0x0080020001000001;

const MACSEC_VALIDATE_DISABLED: u8 = 0;
const MACSEC_VALIDATE_CHECK: u8 = 1;
const MACSEC_VALIDATE_STRICT: u8 = 2;

const MACSEC_OFFLOAD_OFF: u8 = 0;
const MACSEC_OFFLOAD_PHY: u8 = 1;
const MACSEC_OFFLOAD_MAC: u8 = 2;

/// Cipher suite of a MACsec secure channel, see `enum macsec_cipher_id` of
/// the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacSecCipherId {
    GcmAes128,
    GcmAes256,
    GcmAesXpn128,
    GcmAesXpn256,
    Other(u64),
}

impl From<u64> for MacSecCipherId {
    fn from(value: u64) -> Self {
        match value {
            MACSEC_DEFAULT_CIPHER_ID | MACSEC_CIPHER_ID_GCM_AES_128 => {
                Self::GcmAes128
            }
            MACSEC_CIPHER_ID_GCM_AES_256 => Self::GcmAes256,
            MACSEC_CIPHER_ID_GCM_AES_XPN_128 => Self::GcmAesXpn128,
            MACSEC_CIPHER_ID_GCM_AES_XPN_256 => Self::GcmAesXpn256,
            value => Self::Other(value),
        }
    }
}

impl From<MacSecCipherId> for u64 {
    fn from(value: MacSecCipherId) -> Self {
        match value {
            MacSecCipherId::GcmAes128 => MACSEC_CIPHER_ID_GCM_AES_128,
            MacSecCipherId::GcmAes256 => MACSEC_CIPHER_ID_GCM_AES_256,
            MacSecCipherId::GcmAesXpn128 => MACSEC_CIPHER_ID_GCM_AES_XPN_128,
            MacSecCipherId::GcmAesXpn256 => MACSEC_CIPHER_ID_GCM_AES_XPN_256,
            MacSecCipherId::Other(value) => value,
        }
    }
}

/// Validation mode of a MACsec secure channel, see
/// `enum macsec_validation_type` of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacSecValidate {
    Disabled,
    Check,
    Strict,
    Other(u8),
}

impl From<u8> for MacSecValidate {
    fn from(value: u8) -> Self {
        match value {
            MACSEC_VALIDATE_DISABLED => Self::Disabled,
            MACSEC_VALIDATE_CHECK => Self::Check,
            MACSEC_VALIDATE_STRICT => Self::Strict,
            value => Self::Other(value),
        }
    }
}

impl From<MacSecValidate> for u8 {
    fn from(value: MacSecValidate) -> Self {
        match value {
            MacSecValidate::Disabled => MACSEC_VALIDATE_DISABLED,
            MacSecValidate::Check => MACSEC_VALIDATE_CHECK,
            MacSecValidate::Strict => MACSEC_VALIDATE_STRICT,
            MacSecValidate::Other(value) => value,
        }
    }
}

/// Offload mode of a MACsec secure channel, see `enum macsec_offload` of the
/// kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacSecOffload {
    Off,
    Phy,
    Mac,
    Other(u8),
}

impl From<u8> for MacSecOffload {
    fn from(value: u8) -> Self {
        match value {
            MACSEC_OFFLOAD_OFF => Self::Off,
            MACSEC_OFFLOAD_PHY => Self::Phy,
            MACSEC_OFFLOAD_MAC => Self::Mac,
            value => Self::Other(value),
        }
    }
}

impl From<MacSecOffload> for u8 {
    fn from(value: MacSecOffload) -> Self {
        match value {
            MacSecOffload::Off => MACSEC_OFFLOAD_OFF,
            MacSecOffload::Phy => MACSEC_OFFLOAD_PHY,
            MacSecOffload::Mac => MACSEC_OFFLOAD_MAC,
            MacSecOffload::Other(value) => value,
        }
    }
}

const MACSEC_ATTR_IFINDEX: u16 = 1;
const MACSEC_ATTR_RXSC_CONFIG: u16 = 2;
const MACSEC_ATTR_SA_CONFIG: u16 = 3;
const MACSEC_ATTR_SECY: u16 = 4;
const MACSEC_ATTR_TXSA_LIST: u16 = 5;
const MACSEC_ATTR_RXSC_LIST: u16 = 6;
const MACSEC_ATTR_TXSC_STATS: u16 = 7;
const MACSEC_ATTR_SECY_STATS: u16 = 8;
const MACSEC_ATTR_OFFLOAD: u16 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecAttribute {
    Ifindex(u32),
    RxscConfig(Vec<MacsecRxscAttribute>),
    SaConfig(Vec<MacsecSaAttribute>),
    Secy(Vec<MacsecSecyAttribute>),
    TxsaList(Vec<MacsecSaList>),
    RxscList(Vec<MacsecRxscList>),
    TxscStats(Vec<MacsecTxscStatsAttribute>),
    SecyStats(Vec<MacsecSecyStatsAttribute>),
    Offload(Vec<MacsecOffloadAttribute>),
    Other(DefaultNla),
}

impl Nla for MacsecAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Ifindex(_) => MACSEC_ATTR_IFINDEX,
            Self::RxscConfig(_) => MACSEC_ATTR_RXSC_CONFIG,
            Self::SaConfig(_) => MACSEC_ATTR_SA_CONFIG,
            Self::Secy(_) => MACSEC_ATTR_SECY,
            Self::TxsaList(_) => MACSEC_ATTR_TXSA_LIST,
            Self::RxscList(_) => MACSEC_ATTR_RXSC_LIST,
            Self::TxscStats(_) => MACSEC_ATTR_TXSC_STATS,
            Self::SecyStats(_) => MACSEC_ATTR_SECY_STATS,
            Self::Offload(_) => MACSEC_ATTR_OFFLOAD,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Ifindex(value) => append_u32(out, *value),
            Self::RxscConfig(attrs) => attrs.as_slice().emit(out)?,
            Self::SaConfig(attrs) => attrs.as_slice().emit(out)?,
            Self::Secy(attrs) => attrs.as_slice().emit(out)?,
            Self::TxsaList(list) => list.as_slice().emit(out)?,
            Self::RxscList(list) => list.as_slice().emit(out)?,
            Self::TxscStats(attrs) => attrs.as_slice().emit(out)?,
            Self::SecyStats(attrs) => attrs.as_slice().emit(out)?,
            Self::Offload(attrs) => attrs.as_slice().emit(out)?,
            Self::Other(nla) => return nla.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MacsecAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MACSEC_ATTR_IFINDEX => Self::Ifindex(
                parse_u32(payload).context("invalid MACSEC_ATTR_IFINDEX")?,
            ),
            MACSEC_ATTR_RXSC_CONFIG => {
                Self::RxscConfig(parse_attributes(payload)?)
            }
            MACSEC_ATTR_SA_CONFIG => Self::SaConfig(parse_attributes(payload)?),
            MACSEC_ATTR_SECY => Self::Secy(parse_attributes(payload)?),
            MACSEC_ATTR_TXSA_LIST => {
                Self::TxsaList(parse_nested_sa_list(payload)?)
            }
            MACSEC_ATTR_RXSC_LIST => {
                Self::RxscList(parse_nested_rxsc_list(payload)?)
            }
            MACSEC_ATTR_TXSC_STATS => {
                Self::TxscStats(parse_attributes(payload)?)
            }
            MACSEC_ATTR_SECY_STATS => {
                Self::SecyStats(parse_attributes(payload)?)
            }
            MACSEC_ATTR_OFFLOAD => Self::Offload(parse_attributes(payload)?),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown MACSEC NLA type {kind}"))?,
            ),
        })
    }
}

// The elements of `MACSEC_ATTR_TXSA_LIST` and `MACSEC_ATTR_RXSC_LIST` are
// plain nested attributes without a kind of their own: every element is a
// netlink attribute whose payload is another attribute list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacsecSaList {
    /// The kernel uses the index in the list plus one as attribute kind.
    pub kind: u16,
    pub attributes: Vec<MacsecSaAttribute>,
}

impl MacsecSaList {
    pub fn new(kind: u16, attributes: Vec<MacsecSaAttribute>) -> Self {
        Self { kind, attributes }
    }
}

impl Nla for MacsecSaList {
    fn kind(&self) -> u16 {
        self.kind
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacsecRxscList {
    /// The kernel uses the index in the list plus one as attribute kind.
    pub kind: u16,
    pub attributes: Vec<MacsecRxscAttribute>,
}

impl MacsecRxscList {
    pub fn new(kind: u16, attributes: Vec<MacsecRxscAttribute>) -> Self {
        Self { kind, attributes }
    }
}

impl Nla for MacsecRxscList {
    fn kind(&self) -> u16 {
        self.kind
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)
    }
}

fn parse_nested_sa_list(
    payload: &[u8],
) -> Result<Vec<MacsecSaList>, DecodeError> {
    let mut list = Vec::new();
    for nla in NlasIterator::new(payload)? {
        list.push(MacsecSaList {
            kind: nla.kind(),
            attributes: parse_attributes(nla.value())?,
        });
    }
    Ok(list)
}

fn parse_nested_rxsc_list(
    payload: &[u8],
) -> Result<Vec<MacsecRxscList>, DecodeError> {
    let mut list = Vec::new();
    for nla in NlasIterator::new(payload)? {
        list.push(MacsecRxscList {
            kind: nla.kind(),
            attributes: parse_attributes(nla.value())?,
        });
    }
    Ok(list)
}

const MACSEC_SECY_ATTR_SCI: u16 = 1;
const MACSEC_SECY_ATTR_ENCODING_SA: u16 = 2;
const MACSEC_SECY_ATTR_WINDOW: u16 = 3;
const MACSEC_SECY_ATTR_CIPHER_SUITE: u16 = 4;
const MACSEC_SECY_ATTR_ICV_LEN: u16 = 5;
const MACSEC_SECY_ATTR_PROTECT: u16 = 6;
const MACSEC_SECY_ATTR_REPLAY: u16 = 7;
const MACSEC_SECY_ATTR_OPER: u16 = 8;
const MACSEC_SECY_ATTR_VALIDATE: u16 = 9;
const MACSEC_SECY_ATTR_ENCRYPT: u16 = 10;
const MACSEC_SECY_ATTR_INC_SCI: u16 = 11;
const MACSEC_SECY_ATTR_ES: u16 = 12;
const MACSEC_SECY_ATTR_SCB: u16 = 13;
const MACSEC_SECY_ATTR_PAD: u16 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecSecyAttribute {
    Sci(u64),
    EncodingSa(u8),
    Window(u32),
    CipherSuite(MacSecCipherId),
    IcvLen(u8),
    Protect(u8),
    Replay(u8),
    Oper(u8),
    Validate(MacSecValidate),
    Encrypt(u8),
    IncSci(u8),
    Es(u8),
    Scb(u8),
    Pad,
    Other(DefaultNla),
}

impl Nla for MacsecSecyAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Sci(_) => MACSEC_SECY_ATTR_SCI,
            Self::EncodingSa(_) => MACSEC_SECY_ATTR_ENCODING_SA,
            Self::Window(_) => MACSEC_SECY_ATTR_WINDOW,
            Self::CipherSuite(_) => MACSEC_SECY_ATTR_CIPHER_SUITE,
            Self::IcvLen(_) => MACSEC_SECY_ATTR_ICV_LEN,
            Self::Protect(_) => MACSEC_SECY_ATTR_PROTECT,
            Self::Replay(_) => MACSEC_SECY_ATTR_REPLAY,
            Self::Oper(_) => MACSEC_SECY_ATTR_OPER,
            Self::Validate(_) => MACSEC_SECY_ATTR_VALIDATE,
            Self::Encrypt(_) => MACSEC_SECY_ATTR_ENCRYPT,
            Self::IncSci(_) => MACSEC_SECY_ATTR_INC_SCI,
            Self::Es(_) => MACSEC_SECY_ATTR_ES,
            Self::Scb(_) => MACSEC_SECY_ATTR_SCB,
            Self::Pad => MACSEC_SECY_ATTR_PAD,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Sci(value) => append_u64_be(out, *value),
            Self::EncodingSa(value)
            | Self::IcvLen(value)
            | Self::Protect(value)
            | Self::Replay(value)
            | Self::Oper(value)
            | Self::Encrypt(value)
            | Self::IncSci(value)
            | Self::Es(value)
            | Self::Scb(value) => out.push(*value),
            Self::Window(value) => append_u32(out, *value),
            Self::CipherSuite(value) => append_u64(out, (*value).into()),
            Self::Validate(value) => out.push((*value).into()),
            Self::Pad => (),
            Self::Other(nla) => return nla.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MacsecSecyAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MACSEC_SECY_ATTR_SCI => Self::Sci(
                parse_u64_be(payload)
                    .context("invalid MACSEC_SECY_ATTR_SCI")?,
            ),
            MACSEC_SECY_ATTR_ENCODING_SA => Self::EncodingSa(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_ENCODING_SA")?,
            ),
            MACSEC_SECY_ATTR_WINDOW => Self::Window(
                parse_u32(payload)
                    .context("invalid MACSEC_SECY_ATTR_WINDOW")?,
            ),
            MACSEC_SECY_ATTR_CIPHER_SUITE => Self::CipherSuite(
                parse_u64(payload)
                    .context("invalid MACSEC_SECY_ATTR_CIPHER_SUITE")?
                    .into(),
            ),
            MACSEC_SECY_ATTR_ICV_LEN => Self::IcvLen(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_ICV_LEN")?,
            ),
            MACSEC_SECY_ATTR_PROTECT => Self::Protect(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_PROTECT")?,
            ),
            MACSEC_SECY_ATTR_REPLAY => Self::Replay(
                parse_u8(payload).context("invalid MACSEC_SECY_ATTR_REPLAY")?,
            ),
            MACSEC_SECY_ATTR_OPER => Self::Oper(
                parse_u8(payload).context("invalid MACSEC_SECY_ATTR_OPER")?,
            ),
            MACSEC_SECY_ATTR_VALIDATE => Self::Validate(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_VALIDATE")?
                    .into(),
            ),
            MACSEC_SECY_ATTR_ENCRYPT => Self::Encrypt(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_ENCRYPT")?,
            ),
            MACSEC_SECY_ATTR_INC_SCI => Self::IncSci(
                parse_u8(payload)
                    .context("invalid MACSEC_SECY_ATTR_INC_SCI")?,
            ),
            MACSEC_SECY_ATTR_ES => Self::Es(
                parse_u8(payload).context("invalid MACSEC_SECY_ATTR_ES")?,
            ),
            MACSEC_SECY_ATTR_SCB => Self::Scb(
                parse_u8(payload).context("invalid MACSEC_SECY_ATTR_SCB")?,
            ),
            MACSEC_SECY_ATTR_PAD => Self::Pad,
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown MACSEC SECY NLA type {kind}"))?,
            ),
        })
    }
}

const MACSEC_RXSC_ATTR_SCI: u16 = 1;
const MACSEC_RXSC_ATTR_ACTIVE: u16 = 2;
const MACSEC_RXSC_ATTR_SA_LIST: u16 = 3;
const MACSEC_RXSC_ATTR_STATS: u16 = 4;
const MACSEC_RXSC_ATTR_PAD: u16 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecRxscAttribute {
    Sci(u64),
    Active(u8),
    SaList(Vec<MacsecSaList>),
    Stats(Vec<MacsecRxscStatsAttribute>),
    Pad,
    Other(DefaultNla),
}

impl Nla for MacsecRxscAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Sci(_) => MACSEC_RXSC_ATTR_SCI,
            Self::Active(_) => MACSEC_RXSC_ATTR_ACTIVE,
            Self::SaList(_) => MACSEC_RXSC_ATTR_SA_LIST,
            Self::Stats(_) => MACSEC_RXSC_ATTR_STATS,
            Self::Pad => MACSEC_RXSC_ATTR_PAD,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Sci(value) => append_u64_be(out, *value),
            Self::Active(value) => out.push(*value),
            Self::SaList(list) => list.as_slice().emit(out)?,
            Self::Stats(attrs) => attrs.as_slice().emit(out)?,
            Self::Pad => (),
            Self::Other(nla) => return nla.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MacsecRxscAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MACSEC_RXSC_ATTR_SCI => Self::Sci(
                parse_u64_be(payload)
                    .context("invalid MACSEC_RXSC_ATTR_SCI")?,
            ),
            MACSEC_RXSC_ATTR_ACTIVE => Self::Active(
                parse_u8(payload).context("invalid MACSEC_RXSC_ATTR_ACTIVE")?,
            ),
            MACSEC_RXSC_ATTR_SA_LIST => {
                Self::SaList(parse_nested_sa_list(payload)?)
            }
            MACSEC_RXSC_ATTR_STATS => Self::Stats(parse_attributes(payload)?),
            MACSEC_RXSC_ATTR_PAD => Self::Pad,
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown MACSEC RXSC NLA type {kind}"))?,
            ),
        })
    }
}

const MACSEC_SA_ATTR_AN: u16 = 1;
const MACSEC_SA_ATTR_ACTIVE: u16 = 2;
const MACSEC_SA_ATTR_PN: u16 = 3;
const MACSEC_SA_ATTR_KEY: u16 = 4;
const MACSEC_SA_ATTR_KEYID: u16 = 5;
const MACSEC_SA_ATTR_STATS: u16 = 6;
const MACSEC_SA_ATTR_PAD: u16 = 7;
const MACSEC_SA_ATTR_SSCI: u16 = 8;
const MACSEC_SA_ATTR_SALT: u16 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecSaAttribute {
    An(u8),
    Active(u8),
    Pn32(u32),
    Pn64(u64),
    Key(Vec<u8>),
    KeyId(Vec<u8>),
    Stats(Vec<MacsecSaStatsAttribute>),
    Pad,
    Ssci(u32),
    Salt(Vec<u8>),
    Other(DefaultNla),
}

impl Nla for MacsecSaAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::An(_) => MACSEC_SA_ATTR_AN,
            Self::Active(_) => MACSEC_SA_ATTR_ACTIVE,
            Self::Pn32(_) | Self::Pn64(_) => MACSEC_SA_ATTR_PN,
            Self::Key(_) => MACSEC_SA_ATTR_KEY,
            Self::KeyId(_) => MACSEC_SA_ATTR_KEYID,
            Self::Stats(_) => MACSEC_SA_ATTR_STATS,
            Self::Pad => MACSEC_SA_ATTR_PAD,
            Self::Ssci(_) => MACSEC_SA_ATTR_SSCI,
            Self::Salt(_) => MACSEC_SA_ATTR_SALT,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::An(value) | Self::Active(value) => out.push(*value),
            Self::Pn32(value) => append_u32(out, *value),
            Self::Pn64(value) => append_u64(out, *value),
            Self::Key(value) | Self::KeyId(value) | Self::Salt(value) => {
                append_bytes(out, value);
            }
            Self::Stats(attrs) => attrs.as_slice().emit(out)?,
            Self::Pad => (),
            Self::Ssci(value) => append_u32_be(out, *value),
            Self::Other(nla) => return nla.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MacsecSaAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MACSEC_SA_ATTR_AN => Self::An(
                parse_u8(payload).context("invalid MACSEC_SA_ATTR_AN")?,
            ),
            MACSEC_SA_ATTR_ACTIVE => Self::Active(
                parse_u8(payload).context("invalid MACSEC_SA_ATTR_ACTIVE")?,
            ),
            MACSEC_SA_ATTR_PN => {
                if payload.len() == 8 {
                    Self::Pn64(
                        parse_u64(payload)
                            .context("invalid MACSEC_SA_ATTR_PN")?,
                    )
                } else {
                    Self::Pn32(
                        parse_u32(payload)
                            .context("invalid MACSEC_SA_ATTR_PN")?,
                    )
                }
            }
            MACSEC_SA_ATTR_KEY => Self::Key(payload.to_vec()),
            MACSEC_SA_ATTR_KEYID => Self::KeyId(payload.to_vec()),
            MACSEC_SA_ATTR_STATS => Self::Stats(parse_attributes(payload)?),
            MACSEC_SA_ATTR_PAD => Self::Pad,
            MACSEC_SA_ATTR_SSCI => Self::Ssci(
                parse_u32_be(payload).context("invalid MACSEC_SA_ATTR_SSCI")?,
            ),
            MACSEC_SA_ATTR_SALT => Self::Salt(payload.to_vec()),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown MACSEC SA NLA type {kind}"))?,
            ),
        })
    }
}

const MACSEC_OFFLOAD_ATTR_TYPE: u16 = 1;
const MACSEC_OFFLOAD_ATTR_PAD: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecOffloadAttribute {
    Type(MacSecOffload),
    Pad,
    Other(DefaultNla),
}

impl Nla for MacsecOffloadAttribute {
    fn kind(&self) -> u16 {
        match self {
            Self::Type(_) => MACSEC_OFFLOAD_ATTR_TYPE,
            Self::Pad => MACSEC_OFFLOAD_ATTR_PAD,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Type(value) => out.push((*value).into()),
            Self::Pad => (),
            Self::Other(nla) => return nla.emit_value(out),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MacsecOffloadAttribute {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MACSEC_OFFLOAD_ATTR_TYPE => Self::Type(
                parse_u8(payload)
                    .context("invalid MACSEC_OFFLOAD_ATTR_TYPE")?
                    .into(),
            ),
            MACSEC_OFFLOAD_ATTR_PAD => Self::Pad,
            kind => {
                Self::Other(DefaultNla::parse(buf).context(format!(
                    "unknown MACSEC OFFLOAD NLA type {kind}"
                ))?)
            }
        })
    }
}

macro_rules! stats_attribute {
    (
        $name:ident,
        $width:literal,
        $(
            $variant:ident => $kind:ident,
        )+
    ) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum $name {
            $($variant(u64),)+
            Other(DefaultNla),
        }

        impl Nla for $name {
            fn kind(&self) -> u16 {
                match self {
                    $(Self::$variant(_) => $kind,)+
                    Self::Other(nla) => nla.kind(),
                }
            }

            fn emit_value(
                &self,
                out: &mut Vec<u8>,
            ) -> Result<(), EncodeError> {
                match self {
                    $(Self::$variant(value) => {
                        if $width == 4 {
                            let value = u32::try_from(*value).map_err(|_| {
                                EncodeError::new(
                                    EncodeErrorKind::InvalidValue,
                                    "statistics value exceeds u32",
                                )
                            })?;
                            append_u32(out, value);
                        } else {
                            append_u64(out, *value);
                        }
                    })+
                    Self::Other(nla) => return nla.emit_value(out),
                }
                Ok(())
            }
        }

        impl<'a> Parseable<NlaBuffer<'a>> for $name {
            fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
                let payload = buf.value();
                Ok(match buf.kind() {
                    $($kind => Self::$variant(
                        parse_stat_value(payload).context(concat!(
                            "invalid ",
                            stringify!($name),
                            " value",
                        ))?,
                    ),)+
                    kind => Self::Other(DefaultNla::parse(buf).context(
                        format!("unknown {} NLA type {kind}", stringify!($name))
                    )?),
                })
            }
        }
    };
}

fn parse_stat_value(payload: &[u8]) -> Result<u64, DecodeError> {
    match payload.len() {
        1 => Ok(u64::from(parse_u8(payload)?)),
        2 => Ok(u64::from(parse_u16(payload)?)),
        4 => Ok(u64::from(parse_u32(payload)?)),
        8 => parse_u64(payload),
        len => Err(DecodeError::invalid_number(8, len)),
    }
}

const MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED: u16 = 1;
const MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED: u16 = 2;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED: u16 = 3;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED: u16 = 4;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK: u16 = 5;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID: u16 = 6;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE: u16 = 7;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID: u16 = 8;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_USING_SA: u16 = 9;
const MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNUSED_SA: u16 = 10;

stats_attribute!(
    MacsecRxscStatsAttribute,
    8,
    InOctetsValidated => MACSEC_RXSC_STATS_ATTR_IN_OCTETS_VALIDATED,
    InOctetsDecrypted => MACSEC_RXSC_STATS_ATTR_IN_OCTETS_DECRYPTED,
    InPktsUnchecked => MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNCHECKED,
    InPktsDelayed => MACSEC_RXSC_STATS_ATTR_IN_PKTS_DELAYED,
    InPktsOk => MACSEC_RXSC_STATS_ATTR_IN_PKTS_OK,
    InPktsInvalid => MACSEC_RXSC_STATS_ATTR_IN_PKTS_INVALID,
    InPktsLate => MACSEC_RXSC_STATS_ATTR_IN_PKTS_LATE,
    InPktsNotValid => MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_VALID,
    InPktsNotUsingSa => MACSEC_RXSC_STATS_ATTR_IN_PKTS_NOT_USING_SA,
    InPktsUnusedSa => MACSEC_RXSC_STATS_ATTR_IN_PKTS_UNUSED_SA,
);

const MACSEC_SA_STATS_ATTR_IN_PKTS_OK: u16 = 1;
const MACSEC_SA_STATS_ATTR_IN_PKTS_INVALID: u16 = 2;
const MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_VALID: u16 = 3;
const MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_USING_SA: u16 = 4;
const MACSEC_SA_STATS_ATTR_IN_PKTS_UNUSED_SA: u16 = 5;
const MACSEC_SA_STATS_ATTR_OUT_PKTS_PROTECTED: u16 = 6;
const MACSEC_SA_STATS_ATTR_OUT_PKTS_ENCRYPTED: u16 = 7;

stats_attribute!(
    MacsecSaStatsAttribute,
    4,
    InPktsOk => MACSEC_SA_STATS_ATTR_IN_PKTS_OK,
    InPktsInvalid => MACSEC_SA_STATS_ATTR_IN_PKTS_INVALID,
    InPktsNotValid => MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_VALID,
    InPktsNotUsingSa => MACSEC_SA_STATS_ATTR_IN_PKTS_NOT_USING_SA,
    InPktsUnusedSa => MACSEC_SA_STATS_ATTR_IN_PKTS_UNUSED_SA,
    OutPktsProtected => MACSEC_SA_STATS_ATTR_OUT_PKTS_PROTECTED,
    OutPktsEncrypted => MACSEC_SA_STATS_ATTR_OUT_PKTS_ENCRYPTED,
);

const MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED: u16 = 1;
const MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED: u16 = 2;
const MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED: u16 = 3;
const MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED: u16 = 4;

stats_attribute!(
    MacsecTxscStatsAttribute,
    8,
    OutPktsProtected => MACSEC_TXSC_STATS_ATTR_OUT_PKTS_PROTECTED,
    OutPktsEncrypted => MACSEC_TXSC_STATS_ATTR_OUT_PKTS_ENCRYPTED,
    OutOctetsProtected => MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_PROTECTED,
    OutOctetsEncrypted => MACSEC_TXSC_STATS_ATTR_OUT_OCTETS_ENCRYPTED,
);

const MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED: u16 = 1;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED: u16 = 2;
const MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG: u16 = 3;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG: u16 = 4;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG: u16 = 5;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI: u16 = 6;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI: u16 = 7;
const MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN: u16 = 8;

stats_attribute!(
    MacsecSecyStatsAttribute,
    8,
    OutPktsUntagged => MACSEC_SECY_STATS_ATTR_OUT_PKTS_UNTAGGED,
    InPktsUntagged => MACSEC_SECY_STATS_ATTR_IN_PKTS_UNTAGGED,
    OutPktsTooLong => MACSEC_SECY_STATS_ATTR_OUT_PKTS_TOO_LONG,
    InPktsNoTag => MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_TAG,
    InPktsBadTag => MACSEC_SECY_STATS_ATTR_IN_PKTS_BAD_TAG,
    InPktsUnknownSci => MACSEC_SECY_STATS_ATTR_IN_PKTS_UNKNOWN_SCI,
    InPktsNoSci => MACSEC_SECY_STATS_ATTR_IN_PKTS_NO_SCI,
    InPktsOverrun => MACSEC_SECY_STATS_ATTR_IN_PKTS_OVERRUN,
);
