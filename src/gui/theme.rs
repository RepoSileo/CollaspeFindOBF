use iced::widget::{button, container, pick_list, progress_bar, text_input};
use iced::{Background, Border, Color, Theme};
use iced::theme::Palette;

use crate::gui::state::ThemeMode;

pub fn get_palette(mode: ThemeMode, accent: Color) -> Palette {
    match mode {
        ThemeMode::Dark => Palette {
            background: Color::from_rgb(0.12, 0.12, 0.12),
            text: Color::WHITE,
            primary: accent,
            success: Color::from_rgb(0.20, 0.78, 0.35),
            danger: Color::from_rgb(1.0, 0.23, 0.19),
        },
        ThemeMode::Light => Palette {
            background: Color::WHITE,
            text: Color::BLACK,
            primary: accent,
            success: Color::from_rgb(0.20, 0.78, 0.35),
            danger: Color::from_rgb(1.0, 0.23, 0.19),
        },
    }
}

pub const WARNING_COLOR: Color = Color::from_rgb(1.0, 0.80, 0.0);
pub const BORDER_COLOR_DARK: Color = Color::from_rgb(0.25, 0.25, 0.25);
pub const BORDER_COLOR_LIGHT: Color = Color::from_rgb(0.85, 0.85, 0.85);

fn is_dark(theme: &Theme) -> bool {
    matches!(theme.palette().text, Color::WHITE)
}

pub fn border_color(theme: &Theme) -> Color {
    if is_dark(theme) {
        BORDER_COLOR_DARK
    } else {
        BORDER_COLOR_LIGHT
    }
}

pub fn surface_color(theme: &Theme) -> Color {
    let base = theme.palette().background;
    if is_dark(theme) {
        Color::from_rgb(base.r + 0.05, base.g + 0.05, base.b + 0.05)
    } else {
        Color::from_rgb(base.r - 0.03, base.g - 0.03, base.b - 0.03)
    }
}

pub fn sidebar_bg(theme: &Theme) -> Color {
    let base = theme.palette().background;
    if is_dark(theme) {
         Color::from_rgb(base.r - 0.01, base.g - 0.01, base.b - 0.01)
    } else {
         Color::from_rgb(0.96, 0.96, 0.96)
    }
}

pub fn text_secondary(theme: &Theme) -> Color {
    if is_dark(theme) {
        Color::from_rgb(0.55, 0.55, 0.55)
    } else {
        Color::from_rgb(0.40, 0.40, 0.40)
    }
}

pub fn danger_color(score: u8) -> Color {
    match score {
        8..=10 => Color::from_rgb(1.0, 0.23, 0.19),
        5..=7 => Color::from_rgb(1.0, 0.58, 0.0),
        3..=4 => WARNING_COLOR,
        _ => Color::from_rgb(0.20, 0.78, 0.35),
    }
}


pub fn container_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(theme.palette().background.into()),
        text_color: Some(theme.palette().text),
        ..Default::default()
    }
}

pub fn sidebar_container_style(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(sidebar_bg(theme).into()),
        border: Border {
            color: border_color(theme),
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}

pub fn card_style(theme: &Theme) -> container::Style {
    let bg = if is_dark(theme) {
        Color::from_rgba(0.20, 0.20, 0.20, 0.60)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.80)
    };
    
    container::Style {
        background: Some(bg.into()),
        border: Border {
            color: border_color(theme),
            width: 1.0,
            radius: 12.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.1),
            offset: iced::Vector::new(0.0, 5.0),
            blur_radius: 15.0,
        },
        ..Default::default()
    }
}

pub fn button_style(theme: &Theme, status: button::Status) -> button::Style {
    let bg_color = match status {
        button::Status::Hovered => if is_dark(theme) { Color::from_rgb(0.25, 0.25, 0.25) } else { Color::from_rgb(0.90, 0.90, 0.90) },
        button::Status::Pressed => if is_dark(theme) { Color::from_rgb(0.22, 0.22, 0.22) } else { Color::from_rgb(0.85, 0.85, 0.85) },
        _ => surface_color(theme),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: theme.palette().text,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.05),
            offset: iced::Vector::new(0.0, 1.0),
            blur_radius: 2.0,
        },
    }
}

pub fn primary_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let base = theme.palette().primary;
    let bg_color = match status {
        button::Status::Hovered => Color::from_rgb(base.r * 1.1, base.g * 1.1, base.b * 1.1),
        button::Status::Pressed => Color::from_rgb(base.r * 0.9, base.g * 0.9, base.b * 0.9),
        _ => base,
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: Color::WHITE,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(base.r, base.g, base.b, 0.4),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 10.0,
        },
    }
}

pub fn cancel_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let base = theme.palette().danger;
     let bg_color = match status {
        button::Status::Hovered => Color::from_rgb(base.r * 1.1, base.g * 1.1, base.b * 1.1),
        button::Status::Pressed => Color::from_rgb(base.r * 0.9, base.g * 0.9, base.b * 0.9),
        _ => base,
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: Color::WHITE,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 8.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(base.r, base.g, base.b, 0.3),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 10.0,
        },
    }
}

pub fn result_button_style(theme: &Theme, status: button::Status) -> button::Style {
     let bg_color = match status {
        button::Status::Hovered => if is_dark(theme) { Color::from_rgb(0.20, 0.20, 0.20) } else { Color::from_rgb(0.95, 0.95, 0.95) },
        button::Status::Pressed => if is_dark(theme) { Color::from_rgb(0.18, 0.18, 0.18) } else { Color::from_rgb(0.90, 0.90, 0.90) },
        _ => if is_dark(theme) { Color::from_rgb(0.16, 0.16, 0.16) } else { Color::WHITE },
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color: theme.palette().text,
        border: Border {
            color: border_color(theme),
            width: 1.0,
            radius: 10.0.into(),
        },
        shadow: iced::Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.05),
            offset: iced::Vector::new(0.0, 2.0),
            blur_radius: 4.0,
        },
    }
}

pub fn pick_list_style(
    theme: &Theme,
    _status: pick_list::Status,
) -> pick_list::Style {
    pick_list::Style {
        text_color: theme.palette().text,
        placeholder_color: text_secondary(theme),
        handle_color: theme.palette().primary,
        background: Background::Color(surface_color(theme)),
        border: Border {
            radius: 8.0.into(),
            width: 1.0,
            color: border_color(theme),
        },
    }
}

pub fn pick_list_menu_style(theme: &Theme) -> iced::overlay::menu::Style {
    iced::overlay::menu::Style {
        text_color: theme.palette().text,
        background: Background::Color(if is_dark(theme) { Color::from_rgb(0.15, 0.15, 0.15) } else { Color::WHITE }),
        border: Border {
            radius: 8.0.into(),
            width: 1.0,
            color: border_color(theme),
        },
        selected_text_color: Color::WHITE,
        selected_background: Background::Color(theme.palette().primary),
    }
}


pub fn progress_bar_style(theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: Background::Color(surface_color(theme)),
        bar: Background::Color(theme.palette().primary),
        border: Border {
            radius: 4.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
    }
}

pub fn text_input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    text_input::Style {
        background: Background::Color(if is_dark(theme) { Color::from_rgb(0.12, 0.12, 0.12) } else { Color::WHITE }),
        border: Border {
            radius: 8.0.into(),
            width: 1.0,
            color: match status {
                text_input::Status::Focused => theme.palette().primary,
                _ => border_color(theme),
            }
        },
        icon: text_secondary(theme),
        placeholder: text_secondary(theme),
        value: theme.palette().text,
        selection: Color::from_rgba(theme.palette().primary.r, theme.palette().primary.g, theme.palette().primary.b, 0.3),
    }
}

pub fn tab_button_style(theme: &Theme, status: button::Status) -> button::Style {
    let (bg_color, text_color) = match status {
        button::Status::Hovered => (Color::from_rgba(0.5, 0.5, 0.5, 0.1), theme.palette().text),
        button::Status::Pressed => (Color::from_rgba(0.5, 0.5, 0.5, 0.2), theme.palette().text),
        _ => (Color::TRANSPARENT, text_secondary(theme)),
    };

    button::Style {
        background: Some(bg_color.into()),
        text_color,
        border: Border {
            radius: 6.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        shadow: iced::Shadow::default(),
    }
}

pub fn active_tab_button_style(theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(theme.palette().primary.into()),
        text_color: Color::WHITE,
        border: Border {
            radius: 6.0.into(),
            width: 0.0,
            color: Color::TRANSPARENT,
        },
        shadow: iced::Shadow {
             color: Color::from_rgba(theme.palette().primary.r, theme.palette().primary.g, theme.palette().primary.b, 0.4),
             offset: iced::Vector::new(0.0, 2.0),
             blur_radius: 8.0,
        },
    }
}
