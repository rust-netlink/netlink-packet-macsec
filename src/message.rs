// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{MacsecAttribute, attribute::parse_attributes};

const MACSEC_GENL_NAME: &str = "macsec";
const MACSEC_GENL_VERSION: u8 = 1;

const MACSEC_CMD_GET_TXSC: u8 = 0;
const MACSEC_CMD_ADD_RXSC: u8 = 1;
const MACSEC_CMD_DEL_RXSC: u8 = 2;
const MACSEC_CMD_UPD_RXSC: u8 = 3;
const MACSEC_CMD_ADD_TXSA: u8 = 4;
const MACSEC_CMD_DEL_TXSA: u8 = 5;
const MACSEC_CMD_UPD_TXSA: u8 = 6;
const MACSEC_CMD_ADD_RXSA: u8 = 7;
const MACSEC_CMD_DEL_RXSA: u8 = 8;
const MACSEC_CMD_UPD_RXSA: u8 = 9;
const MACSEC_CMD_UPD_OFFLOAD: u8 = 10;

/// Commands of the MACsec generic netlink family, see
/// `enum macsec_nl_commands` of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MacsecCmd {
    GetTxsc,
    AddRxsc,
    DelRxsc,
    UpdRxsc,
    AddTxsa,
    DelTxsa,
    UpdTxsa,
    AddRxsa,
    DelRxsa,
    UpdRxsa,
    UpdOffload,
    Other(u8),
}

impl From<u8> for MacsecCmd {
    fn from(value: u8) -> Self {
        match value {
            MACSEC_CMD_GET_TXSC => Self::GetTxsc,
            MACSEC_CMD_ADD_RXSC => Self::AddRxsc,
            MACSEC_CMD_DEL_RXSC => Self::DelRxsc,
            MACSEC_CMD_UPD_RXSC => Self::UpdRxsc,
            MACSEC_CMD_ADD_TXSA => Self::AddTxsa,
            MACSEC_CMD_DEL_TXSA => Self::DelTxsa,
            MACSEC_CMD_UPD_TXSA => Self::UpdTxsa,
            MACSEC_CMD_ADD_RXSA => Self::AddRxsa,
            MACSEC_CMD_DEL_RXSA => Self::DelRxsa,
            MACSEC_CMD_UPD_RXSA => Self::UpdRxsa,
            MACSEC_CMD_UPD_OFFLOAD => Self::UpdOffload,
            value => Self::Other(value),
        }
    }
}

impl From<MacsecCmd> for u8 {
    fn from(value: MacsecCmd) -> Self {
        match value {
            MacsecCmd::GetTxsc => MACSEC_CMD_GET_TXSC,
            MacsecCmd::AddRxsc => MACSEC_CMD_ADD_RXSC,
            MacsecCmd::DelRxsc => MACSEC_CMD_DEL_RXSC,
            MacsecCmd::UpdRxsc => MACSEC_CMD_UPD_RXSC,
            MacsecCmd::AddTxsa => MACSEC_CMD_ADD_TXSA,
            MacsecCmd::DelTxsa => MACSEC_CMD_DEL_TXSA,
            MacsecCmd::UpdTxsa => MACSEC_CMD_UPD_TXSA,
            MacsecCmd::AddRxsa => MACSEC_CMD_ADD_RXSA,
            MacsecCmd::DelRxsa => MACSEC_CMD_DEL_RXSA,
            MacsecCmd::UpdRxsa => MACSEC_CMD_UPD_RXSA,
            MacsecCmd::UpdOffload => MACSEC_CMD_UPD_OFFLOAD,
            MacsecCmd::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacsecMessage {
    pub cmd: MacsecCmd,
    pub attributes: Vec<MacsecAttribute>,
}

impl MacsecMessage {
    pub fn new(cmd: MacsecCmd) -> Self {
        Self {
            cmd,
            attributes: Vec::new(),
        }
    }
}

impl GenlFamily for MacsecMessage {
    fn family_name() -> &'static str {
        MACSEC_GENL_NAME
    }

    fn version(&self) -> u8 {
        MACSEC_GENL_VERSION
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for MacsecMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attributes.as_slice().emit(out)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for MacsecMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}
