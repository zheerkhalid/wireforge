//! The egui user interface.
mod app;
mod apps_view;
mod charts;
mod connections_view;
mod devices_view;
mod firewall_view;
mod overview;
mod saved_view;
mod settings_view;
mod speed_view;
mod theme;
mod tools_view;
mod widgets;
mod wifi_view;

pub use app::{run, Options};
