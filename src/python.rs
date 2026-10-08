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
use crate::types::{
    BcsmEvent, DpSpecificCriteria, EventSpecificInformationBcsm, EventTypeBcsm, LegId,
    MiscCallInfo, MonitorMode,
};
use crate::InapError;

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    inap,
    InapCodecError,
    PyException,
    "INAP operation encode/decode error (ETS 300 374-1 / ITU-T Q.1218)."
);

fn inap_err(e: InapError) -> PyErr {
    InapCodecError::new_err(e.to_string())
}

fn value_err(message: &str) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(message.to_string())
}

/// A leg from at most one of the two alternatives of LegID.
fn leg_from(sending: &Option<Vec<u8>>, receiving: &Option<Vec<u8>>) -> PyResult<Option<LegId>> {
    match (sending, receiving) {
        (Some(_), Some(_)) => Err(value_err(
            "sending_side_id and receiving_side_id are alternatives of one CHOICE",
        )),
        (Some(leg), None) => Ok(Some(LegId::SendingSideId(leg.clone().into()))),
        (None, Some(leg)) => Ok(Some(LegId::ReceivingSideId(leg.clone().into()))),
        (None, None) => Ok(None),
    }
}

fn leg_parts(leg: Option<&LegId>) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match leg {
        Some(LegId::SendingSideId(leg)) => (Some(leg.to_vec()), None),
        Some(LegId::ReceivingSideId(leg)) => (None, Some(leg.to_vec())),
        None => (None, None),
    }
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
    OrigAttemptAuthorized = 1,
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    OMidCall = 8,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TMidCall = 16,
    TDisconnect = 17,
    TAbandon = 18,
}

impl PyEventTypeBcsm {
    fn to_core(self) -> EventTypeBcsm {
        match self {
            PyEventTypeBcsm::OrigAttemptAuthorized => EventTypeBcsm::OrigAttemptAuthorized,
            PyEventTypeBcsm::OMidCall => EventTypeBcsm::OMidCall,
            PyEventTypeBcsm::TMidCall => EventTypeBcsm::TMidCall,
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
            EventTypeBcsm::OrigAttemptAuthorized => PyEventTypeBcsm::OrigAttemptAuthorized,
            EventTypeBcsm::OMidCall => PyEventTypeBcsm::OMidCall,
            EventTypeBcsm::TMidCall => PyEventTypeBcsm::TMidCall,
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

/// BCSMEvent, one detection point to arm, for
/// [`PyRequestReportBcsmEventArg`].
///
/// `sending_side_id` / `receiving_side_id` are the two alternatives of the
/// `legID` CHOICE (one octet each, `b"\x01"` is leg 1); give at most one.
/// `number_of_digits` / `application_timer` are the two alternatives of
/// `dPSpecificCriteria`; give at most one.
#[pyclass(name = "BcsmEvent", module = "inap._inap", from_py_object)]
#[derive(Clone)]
pub struct PyBcsmEvent {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    #[pyo3(get)]
    pub monitor_mode: PyMonitorMode,
    sending_side_id: Option<Vec<u8>>,
    receiving_side_id: Option<Vec<u8>>,
    #[pyo3(get)]
    pub number_of_digits: Option<u8>,
    #[pyo3(get)]
    pub application_timer: Option<u16>,
}

#[pymethods]
impl PyBcsmEvent {
    #[new]
    #[pyo3(signature = (
        event_type_bcsm,
        monitor_mode,
        *,
        sending_side_id = None,
        receiving_side_id = None,
        number_of_digits = None,
        application_timer = None,
    ))]
    fn new(
        event_type_bcsm: PyEventTypeBcsm,
        monitor_mode: PyMonitorMode,
        sending_side_id: Option<Vec<u8>>,
        receiving_side_id: Option<Vec<u8>>,
        number_of_digits: Option<u8>,
        application_timer: Option<u16>,
    ) -> PyResult<Self> {
        let event = Self {
            event_type_bcsm,
            monitor_mode,
            sending_side_id,
            receiving_side_id,
            number_of_digits,
            application_timer,
        };
        event.to_core()?;
        Ok(event)
    }

    #[getter]
    fn sending_side_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.sending_side_id.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn receiving_side_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.receiving_side_id.as_ref().map(|v| to_pybytes(py, v))
    }

    fn __repr__(&self) -> String {
        format!(
            "BcsmEvent(event_type_bcsm={:?}, monitor_mode={:?})",
            self.event_type_bcsm as i64, self.monitor_mode as i64
        )
    }
}

impl PyBcsmEvent {
    fn to_core(&self) -> PyResult<BcsmEvent> {
        let dp_specific_criteria = match (self.number_of_digits, self.application_timer) {
            (Some(_), Some(_)) => {
                return Err(value_err(
                    "number_of_digits and application_timer are alternatives of one CHOICE",
                ))
            }
            (Some(digits), None) => Some(DpSpecificCriteria::NumberOfDigits(digits)),
            (None, Some(timer)) => Some(DpSpecificCriteria::ApplicationTimer(timer)),
            (None, None) => None,
        };
        Ok(BcsmEvent {
            event_type_bcsm: self.event_type_bcsm.to_core(),
            monitor_mode: self.monitor_mode.to_core(),
            leg_id: leg_from(&self.sending_side_id, &self.receiving_side_id)?,
            dp_specific_criteria,
        })
    }

    fn from_core(e: &BcsmEvent) -> Self {
        let (sending_side_id, receiving_side_id) = leg_parts(e.leg_id.as_ref());
        let (number_of_digits, application_timer) = match e.dp_specific_criteria {
            Some(DpSpecificCriteria::NumberOfDigits(digits)) => (Some(digits), None),
            Some(DpSpecificCriteria::ApplicationTimer(timer)) => (None, Some(timer)),
            None => (None, None),
        };
        Self {
            event_type_bcsm: PyEventTypeBcsm::from_core(e.event_type_bcsm),
            monitor_mode: PyMonitorMode::from_core(e.monitor_mode),
            sending_side_id,
            receiving_side_id,
            number_of_digits,
            application_timer,
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
        let arg = Self::from_core(&core)?;
        Ok(arg)
    }

    fn __repr__(&self) -> String {
        format!("InitialDpArg(service_key={})", self.service_key)
    }
}

impl PyInitialDpArg {
    fn to_core(&self) -> InitialDpArg {
        InitialDpArg {
            called_party_number: self.called_party_number.clone().map(Into::into),
            calling_party_number: self.calling_party_number.clone().map(Into::into),
            calling_partys_category: self.calling_partys_category.clone().map(Into::into),
            ip_available: self.ip_available.clone().map(Into::into),
            location_number: self.location_number.clone().map(Into::into),
            event_type_bcsm: self.event_type_bcsm.map(|e| e.to_core()),
            ..InitialDpArg::new(self.service_key)
        }
    }

    fn from_core(c: &InitialDpArg) -> PyResult<Self> {
        Ok(Self {
            service_key: i64_from(&c.service_key)?,
            called_party_number: c.called_party_number.as_ref().map(|b| b.to_vec()),
            calling_party_number: c.calling_party_number.as_ref().map(|b| b.to_vec()),
            calling_partys_category: c.calling_partys_category.as_ref().map(|b| b.to_vec()),
            ip_available: c.ip_available.as_ref().map(|b| b.to_vec()),
            location_number: c.location_number.as_ref().map(|b| b.to_vec()),
            event_type_bcsm: c.event_type_bcsm.map(PyEventTypeBcsm::from_core),
        })
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
        let arg = Self {
            destination_routing_address: core
                .destination_routing_address
                .iter()
                .map(|b| b.to_vec())
                .collect(),
        };
        Ok(arg)
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
            ..ConnectArg::new(Vec::new().into())
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
        let bytes = crate::encode(&self.to_core()?).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode a RequestReportBCSMEvent argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: RequestReportBcsmEventArg = crate::decode(data).map_err(inap_err)?;
        let arg = Self {
            bcsm_events: core
                .bcsm_events
                .iter()
                .map(PyBcsmEvent::from_core)
                .collect(),
        };
        Ok(arg)
    }

    fn __repr__(&self) -> String {
        format!(
            "RequestReportBcsmEventArg(bcsm_events=[{} events])",
            self.bcsm_events.len()
        )
    }
}

impl PyRequestReportBcsmEventArg {
    fn to_core(&self) -> PyResult<RequestReportBcsmEventArg> {
        let events: PyResult<Vec<BcsmEvent>> =
            self.bcsm_events.iter().map(PyBcsmEvent::to_core).collect();
        Ok(RequestReportBcsmEventArg::new(events?))
    }
}

// ── EventReportBCSM (op 24) ──────────────────────────────────────────────────

/// EventReportBCSM argument, SSF → SCF, report a BCSM event.
///
/// `sending_side_id` / `receiving_side_id` are the two alternatives of the
/// `legID` CHOICE; give at most one (an SSF reports with `receiving_side_id`).
/// `message_type` is the `messageType` of `miscCallInfo`: 0 request, 1
/// notification, `None` to leave the member out (the default is request).
/// `event_specific_information_bcsm` is the BER encoding of the chosen
/// alternative of EventSpecificInformationBCSM, for example
/// `bytes.fromhex("a70480028090")` for an oDisconnectSpecificInfo carrying a
/// release cause; it is checked when the argument is built.
#[pyclass(
    name = "EventReportBcsmArg",
    module = "inap._inap",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct PyEventReportBcsmArg {
    #[pyo3(get)]
    pub event_type_bcsm: PyEventTypeBcsm,
    event_specific_information_bcsm: Option<Vec<u8>>,
    sending_side_id: Option<Vec<u8>>,
    receiving_side_id: Option<Vec<u8>>,
    #[pyo3(get)]
    pub message_type: Option<u8>,
}

#[pymethods]
impl PyEventReportBcsmArg {
    #[new]
    #[pyo3(signature = (
        event_type_bcsm,
        *,
        event_specific_information_bcsm = None,
        sending_side_id = None,
        receiving_side_id = None,
        message_type = None,
    ))]
    fn new(
        event_type_bcsm: PyEventTypeBcsm,
        event_specific_information_bcsm: Option<Vec<u8>>,
        sending_side_id: Option<Vec<u8>>,
        receiving_side_id: Option<Vec<u8>>,
        message_type: Option<u8>,
    ) -> PyResult<Self> {
        let arg = Self {
            event_type_bcsm,
            event_specific_information_bcsm,
            sending_side_id,
            receiving_side_id,
            message_type,
        };
        arg.to_core()?;
        Ok(arg)
    }

    #[getter]
    fn event_specific_information_bcsm<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.event_specific_information_bcsm
            .as_ref()
            .map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn sending_side_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.sending_side_id.as_ref().map(|v| to_pybytes(py, v))
    }
    #[getter]
    fn receiving_side_id<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.receiving_side_id.as_ref().map(|v| to_pybytes(py, v))
    }

    /// Encode the EventReportBCSM argument to BER `bytes`.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = crate::encode(&self.to_core()?).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an EventReportBCSM argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: EventReportBcsmArg = crate::decode(data).map_err(inap_err)?;
        let (sending_side_id, receiving_side_id) = leg_parts(core.leg_id.as_ref());
        let event_specific_information_bcsm = core
            .event_specific_information_bcsm
            .as_ref()
            .map(crate::encode)
            .transpose()
            .map_err(inap_err)?;
        let arg = Self {
            event_type_bcsm: PyEventTypeBcsm::from_core(core.event_type_bcsm),
            event_specific_information_bcsm,
            sending_side_id,
            receiving_side_id,
            message_type: core.misc_call_info.map(|info| info.message_type as u8),
        };
        Ok(arg)
    }

    fn __repr__(&self) -> String {
        format!(
            "EventReportBcsmArg(event_type_bcsm={})",
            self.event_type_bcsm as i64
        )
    }
}

impl PyEventReportBcsmArg {
    fn to_core(&self) -> PyResult<EventReportBcsmArg> {
        let misc_call_info = match self.message_type {
            None => None,
            Some(0) => Some(MiscCallInfo::request()),
            Some(1) => Some(MiscCallInfo::notification()),
            Some(_) => return Err(value_err("message_type is 0 (request) or 1 (notification)")),
        };
        let event_specific_information_bcsm = self
            .event_specific_information_bcsm
            .as_deref()
            .map(crate::decode::<EventSpecificInformationBcsm>)
            .transpose()
            .map_err(inap_err)?;
        Ok(EventReportBcsmArg {
            event_specific_information_bcsm,
            leg_id: leg_from(&self.sending_side_id, &self.receiving_side_id)?,
            misc_call_info,
            ..EventReportBcsmArg::new(self.event_type_bcsm.to_core())
        })
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
        let bytes = crate::encode(&self.to_core()).map_err(inap_err)?;
        Ok(to_pybytes(py, &bytes))
    }

    /// Decode an ApplyCharging argument from BER `bytes`.
    #[classmethod]
    fn decode(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> PyResult<Self> {
        let core: ApplyChargingArg = crate::decode(data).map_err(inap_err)?;
        let party_to_charge = match &core.party_to_charge {
            Some(LegId::SendingSideId(v)) => Some(v.to_vec()),
            Some(LegId::ReceivingSideId(_)) | None => None,
        };
        let arg = Self {
            ach_billing_charging_characteristics: core
                .ach_billing_charging_characteristics
                .to_vec(),
            party_to_charge,
        };
        Ok(arg)
    }

    fn __repr__(&self) -> String {
        "ApplyChargingArg(..)".to_string()
    }
}

impl PyApplyChargingArg {
    fn to_core(&self) -> ApplyChargingArg {
        ApplyChargingArg {
            party_to_charge: self
                .party_to_charge
                .clone()
                .map(|v| LegId::SendingSideId(v.into())),
            ..ApplyChargingArg::new(self.ach_billing_charging_characteristics.clone().into())
        }
    }
}

// ── op_codes + application context (module-level fns) ────────────────────────

/// The name of a well-known INAP CS-1 operation code, if any
/// (e.g. `0 -> "initialDP"`).
#[pyfunction]
fn operation_name(code: i64) -> Option<&'static str> {
    op_codes::operation_name(code)
}

/// The `cs1-ssp-to-scp` application context (`0.4.0.1.1.1.0.0`) as a list of
/// arcs: the dialogue an SSP opens with InitialDP.
#[pyfunction]
fn cs1_ssp_to_scp() -> Vec<u32> {
    ac::CS1_SSP_TO_SCP.to_vec()
}

/// The `cs1-assist-handoff-ssp-to-scp` application context
/// (`0.4.0.1.1.1.1.0`) as a list of arcs.
#[pyfunction]
fn cs1_assist_handoff_ssp_to_scp() -> Vec<u32> {
    ac::CS1_ASSIST_HANDOFF_SSP_TO_SCP.to_vec()
}

/// The `cs1-ip-to-scp` application context (`0.4.0.1.1.1.2.0`) as a list of
/// arcs.
#[pyfunction]
fn cs1_ip_to_scp() -> Vec<u32> {
    ac::CS1_IP_TO_SCP.to_vec()
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
fn i64_from(v: &Integer) -> PyResult<i64> {
    // ServiceKey is Integer4. A value that does not fit is not a service key;
    // say so instead of handing Python a made-up number.
    i64::try_from(v).map_err(|_| InapCodecError::new_err("integer out of range"))
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
    m.add_function(wrap_pyfunction!(cs1_assist_handoff_ssp_to_scp, m)?)?;
    m.add_function(wrap_pyfunction!(cs1_ip_to_scp, m)?)?;

    // Called-party-number encoder (digit string → Q.763 OCTET STRING).
    m.add_function(wrap_pyfunction!(called_party_number, m)?)?;
    m.add_function(wrap_pyfunction!(international_e164, m)?)?;
    m.add("NATURE_INTERNATIONAL", crate::address::NATURE_INTERNATIONAL)?;
    m.add("NATURE_NATIONAL", crate::address::NATURE_NATIONAL)?;
    m.add("PLAN_ISDN", crate::address::PLAN_ISDN)?;

    // Operation codes (ETS 300 374-1 clause 6.4).
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
