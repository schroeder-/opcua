use std::rc::Rc;

use glib::clone;
use gtk::{self, prelude::*};

struct NewConnectionDlgImpl {
    dlg: Rc<gtk::Dialog>,
}

pub(crate) struct NewConnectionDlg {
    data: Rc<NewConnectionDlgImpl>,
}

impl NewConnectionDlg {
    pub fn new(builder: &gtk::Builder) -> Self {
        let dlg: Rc<gtk::Dialog> = Rc::new(builder.get_object("new_connection_dialog").unwrap());
        let connect_btn: Rc<gtk::Button> =
            Rc::new(builder.get_object("new_connection_connect_btn").unwrap());
        let cancel_btn: Rc<gtk::Button> =
            Rc::new(builder.get_object("new_connection_cancel_btn").unwrap());
        let data = Rc::new(NewConnectionDlgImpl { dlg });

        // Connect button
        connect_btn.connect_clicked(clone!(@weak data => move |_| {
            data.on_connect();
        }));

        // Cancel button
        cancel_btn.connect_clicked(clone!(@weak data => move |_| {
            data.on_cancel();
        }));

        Self { data }
    }

    pub fn show(&self) {
        self.data.show();
    }
}

impl NewConnectionDlgImpl {
    pub fn on_cancel(&self) {
        println!("Cancel Clicked!");
        self.dlg.response(gtk::ResponseType::Cancel);
    }

    pub fn on_connect(&self) {
        println!("Connect Clicked!");
        self.dlg.response(gtk::ResponseType::Apply);
    }

    pub fn show(&self) {
        // Connect the buttons
        self.dlg.run();
        self.dlg.hide();
    }
}
