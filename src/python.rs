//! PyO3 bindings, `pip install inap` gives a Rust-backed wheel exposing the
//! **same** INAP CS-1 operation codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add inap` / crates.io consumers pull zero pyo3. Two entry points share
//! one `add_contents()`:
//! * `#[pymodule] fn _inap`, the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)`, mount `inap` as a submodule of another
//!   extension, so a host (e.g. a TCAP stack) can expose inap without a second
//!   shared object.
//!
//! The Python surface mirrors the Rust one: each operation type is a pyclass with
//! `.encode() -> bytes` and a `decode(bytes)` classmethod, both backed by the
//! crate's `rasn` BER codec. The shared enums (`EventTypeBcsm` / `MonitorMode`),
//! the `op_codes` (+ `operation_name`), and the application-context OID helper are
//! exposed too.
//!
//! Coverage: the call-control set (InitialDP, Connect, ReleaseCall,
//! RequestReportBCSMEvent, EventReportBCSM, ApplyCharging). The remaining
//! operations and the specialised-resource / call-information args are Rust-only
//! for now (see `operations` / the README).

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use rasn::types::Integer;

use crate::application_context as ac;
use crate::op_codes;
use crate::operations::{
    ApplyChargingArg, ConnectArg, EventReportBcsmArg, InitialDpArg, ReleaseCallArg,
    RequestReportBcsmEventArg,
};
use crate::types::{BcsmEvent, EventTypeBcsm, LegId, MonitorMode};
use crate::InapError;

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    inap,
    InapCodecError,
    PyException,
    "INAP operation encode/decode error (ITU-T Q.1218 / ETSI EN 300 374-1)."
);

fn inap_err(e: InapError) -> PyErr {
    InapCodecError::new_err(e.to_string())
}

/// `Vec<u8>` → owned Python `bytes`.
fn to_pybytes<'py>(py: Python<'py>, v: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, v)
}

// ── Shared enums ─────────────────────────────────────────────────────────────

/// EventTypeBCSM, Basic Call State Model detection-point events. Integer values
/// are the on-wire ASN.1 ENUMERATED encoding (`OAnswer == 7`).
#[pyclass(
    name = "EventTypeBcsm",
    module = "inap._inap",
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyEventTypeBcsm {
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TDisconnect = 17,
    TAbandon = 18,
}

impl PyEventTypeBcsm {
    fn to_core(self) -> EventTypeBcsm {
        match self {
            PyEventTypeBcsm::CollectedInfo => EventTypeBcsm::CollectedInfo,
            PyEventTypeBcsm::AnalysedInformation => EventTypeBcsm::AnalysedInformation,
            PyEventTypeBcsm::RouteSelectFailure => EventTypeBcsm::RouteSelectFailure,
            PyEventTypeBcsm::OCalledPartyBusy => EventTypeBcsm::OCalledPartyBusy,
            PyEventTypeBcsm::ONoAnswer => EventTypeBcsm::ONoAnswer,
            PyEventTypeBcsm::OAnswer => EventTypeBcsm::OAnswer,
            PyEventTypeBcsm::ODisconnect => EventTypeBcsm::ODisconnect,
            PyEventTypeBcsm::OAbandon => EventTypeBcsm::OAbandon,
            PyEventTypeBcsm::TermAttemptAuthorized => EventTypeBcsm::TermAttemptAuthorized,
            PyEventTypeBcsm::TBusy => EventTypeBcsm::TBusy,
            PyEventTypeBcsm::TNoAnswer => EventTypeBcsm::TNoAnswer,
            PyEventTypeBcsm::TAnswer => EventTypeBcsm::TAnswer,
            PyEventTypeBcsm::TDisconnect => EventTypeBcsm::TDisconnect,
            PyEventTypeBcsm::TAbandon => EventTypeBcsm::TAbandon,
        }
    }

    fn from_core(e: EventTypeBcsm) -> Self {
        match e {
            EventTypeBcsm::CollectedInfo => PyEventTypeBcsm::CollectedInfo,
            EventTypeBcsm::AnalysedInformation => PyEventTypeBcsm::AnalysedInformation,
            EventTypeBcsm::RouteSelectFailure => PyEventTypeBcsm::RouteSelectFailure,
            EventTypeBcsm::OCalledPartyBusy => PyEventTypeBcsm::OCalledPartyBusy,
            EventTypeBcsm::ONoAnswer => PyEventTypeBcsm::ONoAnswer,
            EventTypeBcsm::OAnswer => PyEventTypeBcsm::OAnswer,
            EventTypeBcsm::ODisconnect => PyEventTypeBcsm::ODisconnect,
            EventTypeBcsm::OAbandon => PyEventTypeBcsm::OAbandon,
            EventTypeBcsm::TermAttemptAuthorized => PyEventTypeBcsm::TermAttemptAuthorized,
            EventTypeBcsm::TBusy => PyEventTypeBcsm::TBusy,
            EventTypeBcsm::TNoAnswer => PyEventTypeBcsm::TNoAnswer,
            EventTypeBcsm::TAnswer => PyEventTypeBcsm::TAnswer,
            EventTypeBcsm::TDisconnect => PyEventTypeBcsm::TDisconnect,
            EventTypeBcsm::TAbandon => PyEventTypeBcsm::TAbandon,
        }
    }
}

/// MonitorMode, how a detection point should be reported.
#[pyclass(
    name = "MonitorMode",
    module = "inap._inap",
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PyMonitorMode {
    Interrupted = 0,
    NotifyAndContinue = 1,
    Transparent = 2,
}

impl PyMonitorMode {
    fn to_core(self) -> MonitorMode {
        match self {
            PyMonitorMode::Interrupted => MonitorMode::Interrupted,
            PyMonitorMode::NotifyAndContinue => MonitorMode::NotifyAndContinue,
            PyMonitorMode::Transparent => MonitorMode::Transparent,
        }
    }

    fn from_core(m: MonitorMode) -> Self {
        match m {
            MonitorMode::Interrupted => PyMonitorMode::Interrupted,
            MonitorMode::NotifyAndContinue => PyMonitorMode::NotifyAndContinue,
            MonitorMode::Transparent => PyMonitorMode::Transparent,
        }
    }
}

/// BCSMEvent, one event detection-point configuration entry for
/// [`PyRequestReportBcsmEventArg`].
#[pyclass(name = "BcsmEvent", module = "inap._inap", from_py_object)]
#[derive(Clone)]
pub struct PyBcsmEvent {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    #[pyo3(get)]
    pub monitor_mode: PyMonitorMode,
    leg_id: Option<Vec<u8>>,
}

#[pymethods]
impl PyBcsmEvent {
    #[new]
    #[pyo3(signature = (event_type_bcsm, monitor_mode, *, leg_id = None))]
    fn new(
        event_type_bcsm: PyEventTypeBcsm,
        monitor_mode: PyMonitorMode,
        leg_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            event_type_bcsm,
            monitor_mode,
            leg_id,
        }
    }

    #[getter]
    fn leg_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.leg_id.as_ref().map(|v| to_pybytes(py, v))
    }

    fn __repr__(&self) -> String {
        format!(
            "BcsmEvent(event_type_bcsm={:?}, monitor_mode={:?})",
            self.event_type_bcsm as i64, self.monitor_mode as i64
        )
    }
}

impl PyBcsmEvent {
    fn to_core(&self) -> BcsmEvent {
        BcsmEvent {
            event_type_bcsm: self.event_type_bcsm.to_core(),
            monitor_mode: self.monitor_mode.to_core(),
            leg_id: self.leg_id.clone().map(Into::into),
        }
    }

    fn from_core(e: &BcsmEvent) -> Self {
        Self {
            event_type_bcsm: PyEventTypeBcsm::from_core(e.event_type_bcsm),
            monitor_mode: PyMonitorMode::from_core(e.monitor_mode),
            leg_id: e.leg_id.as_ref().map(|b| b.to_vec()),
        }
    }
}

// ── InitialDP (op 0) ─────────────────────────────────────────────────────────

/// InitialDP argument, SSF → SCF, sent when a call hits a detection point.
/// Address / octet-string fields are `bytes` in their respective ITU-T wire
/// formats; all but `service_key` are optional.
#[pyclass(name = "InitialDpArg", module = "inap._inap", skip_from_py_object)]
#[derive(Clone)]
pub struct PyInitialDpArg {
    #[pyo3(get)]
    pub service_key: i64,
    called_party_number: Option<Vec<u8>>,
    calling_party_number: Option<Vec<u8>>,
    calling_partys_category: Option<Vec<u8>>,
    ip_available: Option<Vec<u8>>,
    location_number: Option<Vec<u8>>,
    event_type_bcsm: Option<PyEventTypeBcsm>,
}

#[pymethods]
impl PyInitialDpArg {
    #[new]
    #[pyo3(signature = (
        service_key,
        *,
        called_party_number = None,
        calling_party_number = None,
        calling_partys_category = None,
        ip_available = None,
        location_number = None,
        event_type_bcsm = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        service_key: i64,
        called_party_number: Option<Vec<u8>>,
        calling_party_number: Option<Vec<u8>>,
        calling_partys_category: Option<Vec<u8>>,
        ip_available: Option<Vec<u8>>,
        location_number: Option<Vec<u8>>,
        event_type_bcsm: Option<PyEventTypeBcsm>,
    ) -> Self {
        Self {
            service_key,
            called_party_number,
            calling_party_number,
            calling_partys_category,
            ip_available,
            location_number,
            event_type_bcsm,
        }
    }

    #[getter]
    fn called_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.called_party_number.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn calling_party_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.calling_party_number
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn calling_partys_category<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.calling_partys_category
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn ip_available<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.ip_available.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn location_number<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.location_number.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn event_type_bcsm(&self) -> Option<PyEventTypeBcsm> {
        self.event_type_bcsm
    }

    /// Encode the InitialDP argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an InitialDP argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: InitialDpArg = crate::decode(data).map_err(inap_err)?;
        Ok(Self::from_core(&core))
    }

    fn __repr__(&self) -> String {
        format!("InitialDpArg(service_key={})", self.service_key)
    }
}

impl PyInitialDpArg {
    fn to_core(&self) -> InitialDpArg {
        InitialDpArg {
            service_key: Integer::from(self.service_key),
            called_party_number: self.called_party_number.clone().map(Into::into),
            calling_party_number: self.calling_party_number.clone().map(Into::into),
            calling_partys_category: self.calling_partys_category.clone().map(Into::into),
            ip_ssp_capabilities: None,
            ip_available: self.ip_available.clone().map(Into::into),
            location_number: self.location_number.clone().map(Into::into),
            original_called_party_id: None,
            high_layer_compatibility: None,
            service_interaction_indicators: None,
            additional_calling_party_number: None,
            forward_call_indicators: None,
            event_type_bcsm: self.event_type_bcsm.map(|e| e.to_core()),
            redirecting_party_id: None,
        }
    }

    fn from_core(c: &InitialDpArg) -> Self {
        Self {
            service_key: i64_from(&c.service_key),
            called_party_number: c.called_party_number.as_ref().map(|b| b.to_vec()),
            calling_party_number: c.calling_party_number.as_ref().map(|b| b.to_vec()),
            calling_partys_category: c.calling_partys_category.as_ref().map(|b| b.to_vec()),
            ip_available: c.ip_available.as_ref().map(|b| b.to_vec()),
            location_number: c.location_number.as_ref().map(|b| b.to_vec()),
            event_type_bcsm: c.event_type_bcsm.map(PyEventTypeBcsm::from_core),
        }
    }
}

// ── Connect (op 20) ──────────────────────────────────────────────────────────

/// Connect argument, SCF → SSF, route the call to one or more destination
/// addresses (`destination_routing_address`, a list of `bytes`).
#[pyclass(name = "ConnectArg", module = "inap._inap", skip_from_py_object)]
#[derive(Clone)]
pub struct PyConnectArg {
    destination_routing_address: Vec<Vec<u8>>,
}

#[pymethods]
impl PyConnectArg {
    #[new]
    fn new(destination_routing_address: Vec<Vec<u8>>) -> Self {
        Self {
            destination_routing_address,
        }
    }

    #[getter]
    fn destination_routing_address<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.destination_routing_address
            .iter()
            .map(|v| to_pybytes(py, v))
            .collect()
    }

    /// Encode the Connect argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a Connect argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ConnectArg = crate::decode(data).map_err(inap_err)?;
        Ok(Self {
            destination_routing_address: core
                .destination_routing_address
                .iter()
                .map(|b| b.to_vec())
                .collect(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "ConnectArg(destination_routing_address=[{} addr])",
            self.destination_routing_address.len()
        )
    }
}

impl PyConnectArg {
    fn to_core(&self) -> ConnectArg {
        ConnectArg {
            destination_routing_address: self
                .destination_routing_address
                .iter()
                .map(|v| v.clone().into())
                .collect(),
            correlation_id: None,
            original_called_party_id: None,
            scf_id: None,
        }
    }
}

// ── ReleaseCall (op 22) ──────────────────────────────────────────────────────

/// ReleaseCall argument, SCF → SSF, release the call with a bare Q.850 cause.
#[pyclass(name = "ReleaseCallArg", module = "inap._inap", skip_from_py_object)]
#[derive(Clone)]
pub struct PyReleaseCallArg {
    cause: Vec<u8>,
}

#[pymethods]
impl PyReleaseCallArg {
    #[new]
    fn new(cause: Vec<u8>) -> Self {
        Self { cause }
    }

    #[getter]
    fn cause<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_pybytes(py, &self.cause)
    }

    /// Encode the ReleaseCall argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = ReleaseCallArg(self.cause.clone().into());
        let bytes = crate::encode(&core).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a ReleaseCall argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ReleaseCallArg = crate::decode(data).map_err(inap_err)?;
        Ok(Self {
            cause: core.0.to_vec(),
        })
    }

    fn __repr__(&self) -> String {
        format!("ReleaseCallArg(cause={} bytes)", self.cause.len())
    }
}

// ── RequestReportBCSMEvent (op 23) ──────────────────────────────────────────

/// RequestReportBCSMEvent argument, SCF → SSF, arm a set of BCSM event
/// detection points (`bcsm_events`, a list of :class:`BcsmEvent`).
#[pyclass(
    name = "RequestReportBcsmEventArg",
    module = "inap._inap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyRequestReportBcsmEventArg {
    bcsm_events: Vec<PyBcsmEvent>,
}

#[pymethods]
impl PyRequestReportBcsmEventArg {
    #[new]
    fn new(bcsm_events: Vec<PyBcsmEvent>) -> Self {
        Self { bcsm_events }
    }

    #[getter]
    fn bcsm_events(&self) -> Vec<PyBcsmEvent> {
        self.bcsm_events.clone()
    }

    /// Encode the RequestReportBCSMEvent argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = RequestReportBcsmEventArg {
            bcsm_events: self.bcsm_events.iter().map(|e| e.to_core()).collect(),
        };
        let bytes = crate::encode(&core).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a RequestReportBCSMEvent argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: RequestReportBcsmEventArg = crate::decode(data).map_err(inap_err)?;
        Ok(Self {
            bcsm_events: core
                .bcsm_events
                .iter()
                .map(PyBcsmEvent::from_core)
                .collect(),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RequestReportBcsmEventArg(bcsm_events=[{} events])",
            self.bcsm_events.len()
        )
    }
}

// ── EventReportBCSM (op 24) ──────────────────────────────────────────────────

/// EventReportBCSM argument, SSF → SCF, report a BCSM event.
#[pyclass(
    name = "EventReportBcsmArg",
    module = "inap._inap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyEventReportBcsmArg {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    misc_call_info: Option<Vec<u8>>,
}

#[pymethods]
impl PyEventReportBcsmArg {
    #[new]
    #[pyo3(signature = (event_type_bcsm, *, misc_call_info = None))]
    fn new(event_type_bcsm: PyEventTypeBcsm, misc_call_info: Option<Vec<u8>>) -> Self {
        Self {
            event_type_bcsm,
            misc_call_info,
        }
    }

    #[getter]
    fn misc_call_info<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.misc_call_info.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the EventReportBCSM argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = EventReportBcsmArg {
            event_type_bcsm: self.event_type_bcsm.to_core(),
            leg_id: None,
            misc_call_info: self.misc_call_info.clone().map(Into::into),
        };
        let bytes = crate::encode(&core).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an EventReportBCSM argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: EventReportBcsmArg = crate::decode(data).map_err(inap_err)?;
        Ok(Self {
            event_type_bcsm: PyEventTypeBcsm::from_core(core.event_type_bcsm),
            misc_call_info: core.misc_call_info.as_ref().map(|b| b.to_vec()),
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "EventReportBcsmArg(event_type_bcsm={})",
            self.event_type_bcsm as i64
        )
    }
}

// ── ApplyCharging (op 35) ────────────────────────────────────────────────────

/// ApplyCharging argument, SCF → SSF, install charging characteristics. The
/// optional `party_to_charge` is the sending-side leg identity (`bytes`).
#[pyclass(name = "ApplyChargingArg", module = "inap._inap", skip_from_py_object)]
#[derive(Clone)]
pub struct PyApplyChargingArg {
    ach_billing_charging_characteristics: Vec<u8>,
    party_to_charge: Option<Vec<u8>>,
}

#[pymethods]
impl PyApplyChargingArg {
    #[new]
    #[pyo3(signature = (ach_billing_charging_characteristics, *, party_to_charge = None))]
    fn new(
        ach_billing_charging_characteristics: Vec<u8>,
        party_to_charge: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ach_billing_charging_characteristics,
            party_to_charge,
        }
    }

    #[getter]
    fn ach_billing_charging_characteristics<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        to_pybytes(py, &self.ach_billing_charging_characteristics)
    }
    #[getter]
    fn party_to_charge<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.party_to_charge.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the ApplyCharging argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let core = ApplyChargingArg {
            ach_billing_charging_characteristics: self
                .ach_billing_charging_characteristics
                .clone()
                .into(),
            party_to_charge: self
                .party_to_charge
                .clone()
                .map(|v| LegId::SendingSideId(v.into())),
        };
        let bytes = crate::encode(&core).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an ApplyCharging argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ApplyChargingArg = crate::decode(data).map_err(inap_err)?;
        let party_to_charge = core.party_to_charge.map(|leg| match leg {
            LegId::SendingSideId(v) | LegId::ReceivingSideId(v) => v.to_vec(),
        });
        Ok(Self {
            ach_billing_charging_characteristics: core
                .ach_billing_charging_characteristics
                .to_vec(),
            party_to_charge,
        })
    }

    fn __repr__(&self) -> String {
        "ApplyChargingArg(..)".to_string()
    }
}

// ── op_codes + application context (module-level fns) ────────────────────────

/// The name of a well-known INAP CS-1 operation code, if any
/// (e.g. `0 -> "initialDP"`).
#[pyfunction]
fn operation_name(code: i64) -> Option<&'static str> {
    op_codes::operation_name(code)
}

/// The `cs1-ssp-to-scp` application-context OID as a tuple of arcs.
#[pyfunction]
fn cs1_ssp_to_scp() -> Vec<u32> {
    ac::cs1_ssp_to_scp().iter().copied().collect()
}

/// Encode a Q.763 Called Party Number from a digit string: the odd/even +
/// nature-of-address octet, the INN + numbering-plan octet, then BCD digits.
#[pyfunction]
#[pyo3(signature = (digits, nature=crate::address::NATURE_INTERNATIONAL, plan=crate::address::PLAN_ISDN, inn=false))]
fn called_party_number(
    py: Python<'_>,
    digits: &str,
    nature: u8,
    plan: u8,
    inn: bool,
) -> PyResult<Py<PyBytes>> {
    let bytes = crate::address::called_party_number(digits, nature, plan, inn).map_err(inap_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

/// Encode an international E.164 Called Party Number (the common CAMEL
/// `destinationRoutingAddress` form).
#[pyfunction]
fn international_e164(py: Python<'_>, digits: &str) -> PyResult<Py<PyBytes>> {
    let bytes = crate::address::international_e164(digits).map_err(inap_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

// ── i64 <- Integer helper ────────────────────────────────────────────────────
fn i64_from(v: &Integer) -> i64 {
    // ServiceKey is a small non-negative INTEGER in practice; fall back to 0 on
    // the (never-hit, synthetic-data) overflow path rather than panic.
    i64::try_from(v).unwrap_or(0)
}

// ── Module wiring ────────────────────────────────────────────────────────────
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("InapCodecError", m.py().get_type::<InapCodecError>())?;

    // Enums.
    m.add_class::<PyEventTypeBcsm>()?;
    m.add_class::<PyMonitorMode>()?;
    m.add_class::<PyBcsmEvent>()?;

    // Operation arguments.
    m.add_class::<PyInitialDpArg>()?;
    m.add_class::<PyConnectArg>()?;
    m.add_class::<PyReleaseCallArg>()?;
    m.add_class::<PyRequestReportBcsmEventArg>()?;
    m.add_class::<PyEventReportBcsmArg>()?;
    m.add_class::<PyApplyChargingArg>()?;

    // Helpers.
    m.add_function(wrap_pyfunction!(operation_name, m)?)?;
    m.add_function(wrap_pyfunction!(cs1_ssp_to_scp, m)?)?;

    // Called-party-number encoder (digit string → Q.763 OCTET STRING).
    m.add_function(wrap_pyfunction!(called_party_number, m)?)?;
    m.add_function(wrap_pyfunction!(international_e164, m)?)?;
    m.add("NATURE_INTERNATIONAL", crate::address::NATURE_INTERNATIONAL)?;
    m.add("NATURE_NATIONAL", crate::address::NATURE_NATIONAL)?;
    m.add("PLAN_ISDN", crate::address::PLAN_ISDN)?;

    // Operation codes (ITU-T Q.1218 / ETSI EN 300 374-1).
    m.add("INITIAL_DP", op_codes::INITIAL_DP)?;
    m.add("CONNECT", op_codes::CONNECT)?;
    m.add("RELEASE_CALL", op_codes::RELEASE_CALL)?;
    m.add(
        "REQUEST_REPORT_BCSM_EVENT",
        op_codes::REQUEST_REPORT_BCSM_EVENT,
    )?;
    m.add("EVENT_REPORT_BCSM", op_codes::EVENT_REPORT_BCSM)?;
    m.add("APPLY_CHARGING", op_codes::APPLY_CHARGING)?;
    m.add(
        "ESTABLISH_TEMPORARY_CONNECTION",
        op_codes::ESTABLISH_TEMPORARY_CONNECTION,
    )?;
    m.add("CONNECT_TO_RESOURCE", op_codes::CONNECT_TO_RESOURCE)?;
    m.add("CONTINUE", op_codes::CONTINUE)?;
    m.add("ACTIVITY_TEST", op_codes::ACTIVITY_TEST)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "inap._inap"`).
#[pymodule]
fn _inap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build an `inap` submodule and attach it to `parent`,
/// so a host extension can expose inap without a second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "inap")?;
    add_contents(&m)?;
    parent.setattr("inap", &m)?;
    Ok(())
}
