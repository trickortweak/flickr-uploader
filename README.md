flickr-uploader
===============

Upload a directory of media to Flickr to use as a backup to your local storage.

## Features:
* Uploads both images and movies (JPG, PNG, GIF, AVI, MOV files)
* Stores image information locally using a simple SQLite database
* Automatically creates "Sets" based on the folder name the media is in
* Ignores ".picasabackup" directory
* Automatically removes images from Flickr when they are removed from your local hard drive

## Requirements:

* Python 2.7+
* File write access (for the token and local database)
* Flickr API key (free)

## Setup:
Go to http://www.flickr.com/services/apps/create/apply and apply for an API key
Edit the following variables near the top in the script:


* FILES_DIR = "files/"
* FLICKR = {
        "title"                 : "",
        "description"           : "",
        "tags"                  : "auto-upload",
        "is_public"             : "0",
        "is_friend"             : "0",
        "is_family"             : "1" 
        }
* SLEEP_TIME = 1 * 60
* DRIP_TIME = 1 * 60
* DB_PATH = os.path.join(FILES_DIR, "fickerdb")
* FLICKR["api_key"] = ""
* FLICKR["secret"] = ""

Place the file uploadr.py in any directory and run:

$ ./uploadr.py

It will crawl through all the files from the FILES_DIR directory and begin the upload process.
