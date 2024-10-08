use mpris::PlayerFinder;
use notify_rust::Notification;
fn main() {
    let player = PlayerFinder::new()
        .expect("Could not connect to D-Bus")
        .find_active()
        .expect("Could not find active player");

    println!(
        "Showing event stream for player {}...\n(Exit with Ctrl-C)\n",
        player.identity()
    );

    let events = player.events().expect("Could not start event stream");

    for event in events {
        match event {
            Ok(event) => match event {
                mpris::Event::TrackChanged(metadata) => {
                    if !metadata.art_url().unwrap().is_empty()
                        && metadata.track_id().is_some()
                        && !metadata.title().unwrap().is_empty()
                    {
                        let _ = Notification::new()
                            .summary("Now playing")
                            .body(metadata.title().unwrap())
                            .icon("emblem-music-symbolic")
                            .show();
                    } else {
                        continue;
                    };
                }
                _ => {}
            },
            Err(err) => {
                println!("D-Bus error: {}. Aborting.", err);
                break;
            }
        }
    }

    println!("Event stream ended.");
}

