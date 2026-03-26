"""Scanner modules for ARCADA."""

from arcada.scanners.dependency import DependencyScanner
from arcada.scanners.supply_chain import SupplyChainScanner
from arcada.scanners.secrets import SecretScanner
from arcada.scanners.network import NetworkScanner
from arcada.scanners.code_exec import CodeExecScanner
from arcada.scanners.ai_risks import AIRisksScanner
from arcada.scanners.agent_risks import AgentRisksScanner
from arcada.scanners.runtime import RuntimeScanner
from arcada.scanners.abuse import AbuseScanner
from arcada.scanners.trust_model import TrustModelScanner
from arcada.scanners.dep_source import DepSourceScanner
from arcada.scanners.package_metadata import PackageMetadataScanner
from arcada.scanners.dep_behavior import DepBehaviorScanner
from arcada.scanners.js_ast import JsAstScanner
from arcada.scanners.go_risks import GoRisksScanner
from arcada.scanners.taint_scanner import TaintScanner
from arcada.scanners.binary import BinaryScanner
from arcada.scanners.cicd import CICDScanner
from arcada.scanners.crossfile_taint import CrossFileTaintScanner
from arcada.scanners.sandbox import SandboxScanner
from arcada.scanners.crypto_risks import CryptoRisksScanner
from arcada.scanners.homoglyph import HomoglyphScanner
from arcada.scanners.llm_exfil import LLMExfilScanner
from arcada.scanners.sca import SCAScanner
from arcada.scanners.obfuscation import ObfuscationScanner
from arcada.scanners.reachability import ReachabilityScanner
from arcada.scanners.threat_intel import ThreatIntelScanner
from arcada.scanners.behavior import BehaviorScanner
from arcada.scanners.ml_detector import HeuristicDetectorScanner
from arcada.scanners.model_security import ModelSecurityScanner

# Standard scanners (run on project code)
ALL_SCANNERS = [
    DependencyScanner,
    SupplyChainScanner,
    SecretScanner,
    NetworkScanner,
    CodeExecScanner,
    AIRisksScanner,
    AgentRisksScanner,
    RuntimeScanner,
    AbuseScanner,
    TrustModelScanner,
    JsAstScanner,
    GoRisksScanner,
    TaintScanner,
    BinaryScanner,
    CICDScanner,
    CrossFileTaintScanner,
    SandboxScanner,
    CryptoRisksScanner,
    HomoglyphScanner,
    LLMExfilScanner,
    SCAScanner,
    ObfuscationScanner,
    ReachabilityScanner,
    ThreatIntelScanner,
    BehaviorScanner,
    HeuristicDetectorScanner,
    ModelSecurityScanner,
]

# Fast scanners for basic scans (subset of ALL_SCANNERS)
FAST_SCANNERS = [
    DependencyScanner,  # Quick dependency analysis
    SecretScanner,  # Fast secret detection
    CodeExecScanner,  # Code execution risks
    AIRisksScanner,  # AI-specific risks
    NetworkScanner,  # Network calls detection
]

# Deep scanners (run on installed dependency code)
DEEP_SCANNERS = [
    DepSourceScanner,
    PackageMetadataScanner,
    DepBehaviorScanner,
    CryptoRisksScanner,
    HomoglyphScanner,
    LLMExfilScanner,
    SCAScanner,
    ObfuscationScanner,
    ReachabilityScanner,
    ThreatIntelScanner,
    BehaviorScanner,
    HeuristicDetectorScanner,
    ModelSecurityScanner,
]

SCANNER_MAP = {s.name: s for s in ALL_SCANNERS}
DEEP_SCANNER_MAP = {s.name: s for s in DEEP_SCANNERS}
FAST_SCANNER_MAP = {s.name: s for s in FAST_SCANNERS}
