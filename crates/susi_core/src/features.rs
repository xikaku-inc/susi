use serde::Serialize;

pub const IMU_OPTICAL_FUSION: &str = "imu_optical_fusion";
pub const VEHICULAR_FUSION: &str = "vehicular_fusion";
pub const DIFFERENTIAL_IMU_FUSION: &str = "differential_imu_fusion";

pub const ALL_FEATURES: &[FeatureInfo] = &[
    FeatureInfo {
        id: IMU_OPTICAL_FUSION,
        label: "IMU-Optical Fusion",
        description: "6-DOF EKF fusing IMU with optical tracking (includes Full 6-DOF Fusion)",
    },
    FeatureInfo {
        id: VEHICULAR_FUSION,
        label: "Vehicular Fusion",
        description: "GNSS-IMU, Odometry-IMU, and Full Vehicle Fusion filters",
    },
    FeatureInfo {
        id: DIFFERENTIAL_IMU_FUSION,
        label: "Differential IMU",
        description: "Differential orientation between two IMU sensors",
    },
];

#[derive(Debug, Clone, Serialize)]
pub struct FeatureInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}
