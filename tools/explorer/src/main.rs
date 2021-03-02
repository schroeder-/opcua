use std::rc::Rc;

use glib::clone;
use gtk::{self, prelude::*};

use new_connection_dlg::NewConnectionDlg;

mod new_connection_dlg;

fn main() {
    App::run();
}

struct App {
    pub builder: Rc<gtk::Builder>,
    pub model: AppModel,
    toolbar_connect_btn: Rc<gtk::ToolButton>,
    toolbar_disconnect_btn: Rc<gtk::ToolButton>,
}

struct AppModel {}

impl App {
    pub fn run() {
        if gtk::init().is_err() {
            println!("Failed to initialize GTK.");
            return;
        }

        // The user interface is defined as a .glade file
        let glade_src = include_str!("ui.glade");
        let builder = Rc::new(gtk::Builder::from_string(glade_src));

        let toolbar_connect_btn: Rc<gtk::ToolButton> =
            Rc::new(builder.get_object("toolbar_connect_btn").unwrap());

        let toolbar_disconnect_btn: Rc<gtk::ToolButton> =
            Rc::new(builder.get_object("toolbar_disconnect_btn").unwrap());

        let app = Rc::new(App {
            builder,
            toolbar_connect_btn,
            toolbar_disconnect_btn,
            model: AppModel {},
        });

        // Hook up the toolbar buttons
        app.toolbar_connect_btn
            .connect_clicked(clone!(@weak app => move |_| {
                app.on_connect();
            }));

        app.toolbar_disconnect_btn
            .connect_clicked(clone!(@weak app => move |_| {
                app.on_disconnect();
            }));

        // Address space explorer pane
        // TODO

        // Monitored item pane
        // TODO

        // Monitored item properties pane
        // TODO

        // Log / console window
        // TODO

        let main_window: gtk::ApplicationWindow = app.builder.get_object("main_window").unwrap();
        main_window.connect_delete_event(|_, _| {
            println!("Application is closing");
            gtk::main_quit();
            Inhibit(false)
        });

        app.update_state();

        main_window.show_all();

        gtk::main();
    }

    pub fn on_connect(&self) {
        println!("Clicked!");
        let dlg = NewConnectionDlg::new(&self.builder);
        dlg.show();
    }

    pub fn on_disconnect(&self) {
        println!("Disconnect Clicked!");
    }

    fn is_connected(&self) -> bool {
        false
    }

    pub fn update_state(&self) {
        let is_connected = self.is_connected();
        self.toolbar_connect_btn.set_sensitive(!is_connected);
        self.toolbar_disconnect_btn.set_sensitive(is_connected);
    }
}
