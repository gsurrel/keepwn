mod checkpwn;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = clap::App::new("KeePwn")
        .version("0.1")
        .author("Grégoire Surrel")
        .about(r"Checks a KeePass database against the Have I Been Pwned service (https://haveibeenpwned.com/)

Note: this tool performs network requests, but send only a fraction of the password hash,
      thus protecting your password.")
        .arg(
            clap::Arg::with_name("email")
                .short("e")
                .long("email")
                .help("List all the emails from the database")
                .takes_value(false),
        )
        .arg(
            clap::Arg::with_name("password")
                .short("p")
                .long("password")
                .help("Check whether your passwords has been leaked")
                .takes_value(false),
        )
        .arg(
            clap::Arg::with_name("INPUT")
                .help("Sets the KeePass file to use")
                .required(true)
                .index(1),
        )
        .get_matches();

    // Handle to file path
    let database_path = matches
        .value_of_os("INPUT")
        .expect("Couldn't retrieve the database name from the arguments");
    let database_path = std::path::Path::new(database_path);
    let db_handle = &mut std::fs::File::open(database_path).expect("Could not read database file");

    // Prompt for user password
    let prompt = match database_path.file_name() {
        Some(name) => format!("Password to unlock {}: ", name.to_string_lossy()),
        None => "Password to unlock the database: ".to_string(),
    };
    let pass = rpassword::prompt_password_stdout(&prompt).expect("Could not read the password");

    // Open the file
    let db = keepass::Database::open(
        db_handle,   // the database
        Some(&pass), // password
        None,        // keyfile
    )
    .expect("Incorrect password");

    // List of emails seen
    let mut emails = std::collections::HashSet::new();

    // Iterate over all Nodes in the database
    // There is no caching of already seen emails nor passwords yet
    let _: Vec<()> = db
        .root
        .iter()
        .filter_map(|node| {
            // Filter out all the groups, we are interested only in the entries
            if let keepass::Node::Entry(e) = node {
                Some(e)
            } else {
                None
            }
        })
        .map(|entry| {
            let title = entry.get_title().unwrap();
            let user = entry.get_username().unwrap();
            let pass = entry.get_password().unwrap();
            if matches.is_present("email") && fast_chemail::is_valid_email(user) {
                emails.insert(user);
            }
            if matches.is_present("password") {
                print!("Entry '{0}' (user '{1}'): ", title, user);
                let password = checkpwn::api::PassArg {
                    password: pass.to_string(),
                };
                checkpwn::pass_check(&password);
            }
        })
        .collect();

    if matches.is_present("email") {
        println!("\nList of unique emails for manual check:");
        for email in emails {
            println!("{}", email);
        }
    }

    Ok(())
}