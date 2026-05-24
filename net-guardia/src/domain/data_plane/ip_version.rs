use serde::Serialize;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

impl IpVersion {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            4 => Some(Self::V4),
            6 => Some(Self::V6),
            _ => None,
        }
    }

    pub const fn is_v6(self) -> bool {
        matches!(self, Self::V6)
    }
}

impl From<IpVersion> for u8 {
    fn from(value: IpVersion) -> Self {
        value.as_u8()
    }
}

impl TryFrom<u8> for IpVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(())
    }
}

impl Serialize for IpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}
