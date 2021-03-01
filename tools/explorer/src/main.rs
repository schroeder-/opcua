use gtk::{self, prelude::*};

mod new_connection_dlg;

use new_connection_dlg::NewConnectionDlg;

fn main() {
    if gtk::init().is_err() {
        println!("Failed to initialize GTK.");
        return;
    }

    // The user interface is defined as a .glade file
    let glade_src = include_str!("ui.glade");
    let builder = gtk::Builder::from_string(glade_src);

    let main_window: gtk::ApplicationWindow = builder.get_object("main_window").unwrap();

    // Address space explorer pane
    // TODO

    // Monitored item pane
    // TODO

    // Monitored item properties pane
    // TODO

    // Log / console window
    // TODO

    // TODO this button will be removed in due course
    let btn: gtk::Button = builder.get_object("test").unwrap();
    btn.connect_clicked(move |_| {
        println!("Clicked!");
        let dlg = NewConnectionDlg::new(&builder);
        dlg.show();
    });

    main_window.connect_delete_event(|_, _| {
        println!("Application is closing");
        gtk::main_quit();
        Inhibit(false)
    });

    main_window.show_all();

    gtk::main();
}
