//! Drawing for broker mode.

use bas_broker::protocol::EntryKind;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, ListItem, Paragraph, Widget, Wrap};

use crate::broker::{
    AddField, AddForm, BrokerApp, Confirm, Connection, Focus, Message, Modal, Request, RequestState,
};
use crate::ui::{centered, field_line, panel, render_list};

/// Most request rows the requests panel shows before it scrolls.
const REQUEST_ROWS: usize = 8;

impl Widget for &BrokerApp {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let rows = self.requests.len().clamp(1, REQUEST_ROWS);
        let [header, body, requests, status, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(u16::try_from(rows + 2).unwrap_or(u16::MAX)),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);
        self.render_header(header, buf);
        let [list, detail] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas(body);
        self.render_entries(list, buf);
        self.render_detail(detail, buf);
        self.render_requests(requests, buf);
        let message = match &self.message {
            Message::Info(text) => Line::from(format!(" {text}")),
            Message::Error(text) => Line::from(format!(" {text}")).fg(Color::Red).bold(),
        };
        message.render(status, buf);
        Line::from(self.key_hints()).dim().render(keys, buf);
        if let Some(modal) = &self.modal {
            self.render_modal(modal, area, buf);
        }
    }
}

impl BrokerApp {
    fn render_header(&self, area: Rect, buf: &mut Buffer) {
        let state = match &self.connection {
            Connection::Connecting => "connecting".to_owned(),
            Connection::Connected {
                version,
                policy_hash,
            } => format!(
                "broker {version} | policy {}",
                policy_hash.get(..12).unwrap_or(policy_hash)
            ),
            Connection::Failed(_) => "unreachable".to_owned(),
        };
        Line::from(vec![
            " bas-tui ".bold().reversed(),
            Span::raw(format!(
                " Broker {} | {state} | values stay in the broker",
                self.socket().display()
            )),
        ])
        .render(area, buf);
    }

    fn focused_panel(&self, title: &str, focus: Focus) -> Block<'static> {
        let block = panel(title);
        if self.focus == focus {
            block.border_style(Style::new().fg(Color::Yellow))
        } else {
            block
        }
    }

    fn render_entries(&self, area: Rect, buf: &mut Buffer) {
        let block = self.focused_panel("Policy entries", Focus::Entries);
        if let Connection::Failed(error) = &self.connection {
            Paragraph::new(vec![
                Line::from("The broker did not answer.").bold(),
                Line::from(error.clone()).fg(Color::Red),
                Line::default(),
                Line::from("Press g to try again."),
            ])
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
            return;
        }
        if let Some(error) = &self.policy_error {
            Paragraph::new(Line::from(error.clone()).fg(Color::Red))
                .block(block)
                .wrap(Wrap { trim: false })
                .render(area, buf);
            return;
        }
        let Some(entries) = &self.entries else {
            Paragraph::new("Reading the active policy")
                .block(block)
                .render(area, buf);
            return;
        };
        if entries.is_empty() {
            Paragraph::new("The active policy has no entries. Press a to add a proxy secret, or e to edit the policy.")
                .block(block)
                .wrap(Wrap { trim: false })
                .render(area, buf);
            return;
        }
        let rows = entries.iter().map(|entry| {
            ListItem::new(Line::from(vec![
                Span::raw(entry.name.clone()),
                Span::raw(format!("  {}", kind_label(entry.kind))).dim(),
            ]))
        });
        render_list(rows, self.selected, block, area, buf);
    }

    fn render_detail(&self, area: Rect, buf: &mut Buffer) {
        let block = panel("Entry");
        let Some(entry) = self.selected_entry() else {
            Paragraph::new("").block(block).render(area, buf);
            return;
        };
        let mut lines = vec![
            field_line("Name", &entry.name),
            field_line("Kind", kind_label(entry.kind)),
            Line::default(),
        ];
        for (label, text) in &entry.details {
            lines.push(field_line(label, text));
        }
        lines.push(Line::default());
        lines.push(
            Line::from(match entry.kind {
                EntryKind::Secret => {
                    "r rotate: you type the new value on the approval page, never here"
                }
                EntryKind::Github | EntryKind::Tailscale => {
                    "r rotate: drops the cached tokens at once; the next request mints new ones"
                }
                EntryKind::Ssh => "Replace an ssh key with a policy change (e)",
            })
            .dim(),
        );
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .render(area, buf);
    }

    fn render_requests(&self, area: Rect, buf: &mut Buffer) {
        let block = self.focused_panel("Requests", Focus::Requests);
        if self.requests.is_empty() {
            Paragraph::new("No requests yet. Requests you start, and pending ones from other clients, show here.")
                .block(block)
                .wrap(Wrap { trim: false })
                .render(area, buf);
            return;
        }
        let rows = self.requests.iter().map(request_row);
        render_list(rows, self.request_selected, block, area, buf);
    }

    fn key_hints(&self) -> String {
        let hints = match (&self.modal, self.focus) {
            (Some(Modal::Add(_)), _) => {
                "type  Tab or Enter next field  Shift-Tab back  Ctrl-S or Enter on last field send  Esc cancel"
            }
            (Some(Modal::Confirm(_)), _) => "y or Enter send  n or Esc cancel",
            (Some(_), _) => "any key closes",
            (None, Focus::Entries) => {
                "a add  r rotate  e edit policy  p passkey  g refresh  Tab requests  ? keys  q quit"
            }
            (None, Focus::Requests) => {
                "Enter details  c copy approval page  g refresh  Tab entries  ? keys  q quit"
            }
        };
        format!(" {hints}")
    }

    fn render_modal(&self, modal: &Modal, area: Rect, buf: &mut Buffer) {
        let (title, lines): (&str, Vec<Line>) = match modal {
            Modal::Help => ("Keys", help_lines()),
            Modal::Add(form) => ("Add a proxy secret", add_lines(form)),
            Modal::Confirm(confirm) => ("Confirm", confirm_lines(confirm)),
            Modal::Details(key) => (
                "Request",
                self.request(*key).map_or_else(Vec::new, details_lines),
            ),
        };
        let height = u16::try_from(lines.len() + 2)
            .unwrap_or(u16::MAX)
            .min(area.height);
        let popup = centered(area, 90.min(area.width), height);
        Clear.render(popup, buf);
        Paragraph::new(lines)
            .block(panel(title))
            .wrap(Wrap { trim: false })
            .render(popup, buf);
    }
}

fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Secret => "proxy secret",
        EntryKind::Ssh => "ssh key",
        EntryKind::Github => "GitHub App",
        EntryKind::Tailscale => "Tailscale OAuth client",
    }
}

fn state_span(state: &RequestState) -> Span<'static> {
    let (text, color) = match state {
        RequestState::Sending => ("sending ", Color::Yellow),
        RequestState::Pending => ("pending ", Color::Yellow),
        RequestState::Approved(_) => ("approved", Color::Green),
        RequestState::Done(_) => ("done    ", Color::Green),
        RequestState::Denied => ("denied  ", Color::Red),
        RequestState::Expired => ("expired ", Color::Red),
        RequestState::Refused(_) => ("refused ", Color::Red),
        RequestState::Failed(_) => ("failed  ", Color::Red),
    };
    Span::styled(text, Style::new().fg(color).add_modifier(Modifier::BOLD))
}

fn request_row(request: &Request) -> ListItem<'static> {
    let note = match &request.state {
        RequestState::Pending => request
            .url
            .as_ref()
            .map(|url| format!("approve at {url}"))
            .unwrap_or_default(),
        RequestState::Approved(text)
        | RequestState::Done(text)
        | RequestState::Refused(text)
        | RequestState::Failed(text) => text.clone(),
        RequestState::Sending | RequestState::Denied | RequestState::Expired => String::new(),
    };
    ListItem::new(Line::from(vec![
        state_span(&request.state),
        Span::raw(format!("  {}", request.action)),
        Span::raw(format!("  {note}")).dim(),
    ]))
}

fn details_lines(request: &Request) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::raw("State: ").bold(),
            state_span(&request.state),
        ]),
        field_line("Request", &request.action),
        field_line(
            "Started by",
            if request.mine {
                "this app"
            } else {
                "another client"
            },
        ),
    ];
    if let Some(id) = &request.id {
        lines.push(field_line("Approval", id));
    }
    if let Some(url) = &request.url {
        lines.push(field_line("Approval page", url));
    }
    match &request.state {
        RequestState::Approved(text) | RequestState::Done(text) => {
            lines.push(field_line("Result", text));
        }
        RequestState::Refused(text) => {
            lines.push(field_line("Refused, nothing changed", text));
        }
        RequestState::Failed(text) => lines.push(field_line("Failed", text)),
        _ => {}
    }
    if let Some(diff) = &request.diff {
        lines.push(Line::default());
        lines.push("Diff from the active policy".bold().into());
        for line in diff.lines() {
            let style = if line.starts_with('+') && !line.starts_with("+++") {
                Style::new().fg(Color::Green)
            } else if line.starts_with('-') && !line.starts_with("---") {
                Style::new().fg(Color::Red)
            } else {
                Style::new()
            };
            lines.push(Line::styled(line.to_owned(), style));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from("Press any key to close").dim());
    lines
}

fn add_lines(form: &AddForm) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("The broker opens an approval. You type the value on the phone, never here.")
            .dim(),
        Line::default(),
    ];
    for field in AddField::ALL {
        let focused = field == form.focus;
        let style = if focused {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new()
        };
        let marker = if focused { "> " } else { "  " };
        let cursor = if focused { "_" } else { "" };
        lines.push(Line::styled(
            format!("{marker}{}", field.label()),
            style.add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            format!("  {}{cursor}", form.text(field)),
            style,
        ));
    }
    lines
}

fn confirm_lines(confirm: &Confirm) -> Vec<Line<'static>> {
    let text = match confirm {
        Confirm::Rotate { name, minted: true } => vec![
            format!("Rotate {name}?"),
            "The broker drops its cached tokens at once. No approval is needed.".to_owned(),
        ],
        Confirm::Rotate {
            name,
            minted: false,
        } => vec![
            format!("Rotate {name}?"),
            "The broker opens an approval. You type the new value on the phone.".to_owned(),
        ],
        Confirm::Passkey => vec![
            "Enroll one more passkey?".to_owned(),
            "An enrolled passkey approves it, and the approving phone shows a one-time link."
                .to_owned(),
        ],
    };
    let mut lines: Vec<Line> = text.into_iter().map(Line::from).collect();
    lines.push(Line::default());
    lines.push(Line::from("y or Enter send  n or Esc cancel").dim());
    lines
}

fn help_lines() -> Vec<Line<'static>> {
    [
        "Broker mode manages the broker's policy. No value ever reaches this app.",
        "",
        "Everywhere: ? keys, g refresh, Tab switch list, q or Esc quit, Ctrl-C quit",
        "Lists: Up/Down or k/j move",
        "Entries: a add a proxy secret, r rotate the selected entry,",
        "         e edit the policy proposal in $VISUAL or $EDITOR, p enroll a passkey",
        "Requests: Enter details and diff, c copy the approval page address",
        "",
        "Every change waits for a passkey on the approval page. The requests list shows",
        "sending, pending, approved, done, denied, expired, refused, and failed requests.",
        "",
        "Press any key to close",
    ]
    .into_iter()
    .map(Line::from)
    .collect()
}
