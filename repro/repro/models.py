from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel

AddressOrNetwork = IPv4Address | IPv4Network


class ProbeConfig(BaseModel):
    accepts_input: bool = False
    verbose: bool = False


class CommandProbeConfig(ProbeConfig):
    command: str
    targets: list[AddressOrNetwork] = []


class Config(BaseModel):
    interface: str
    timeout: int = 10


class Finding(BaseModel):
    src: str
    ttl: int
    protocol: int
    proto_details: str


class Report(BaseModel):
    meta: dict
    findings: list[Finding]
