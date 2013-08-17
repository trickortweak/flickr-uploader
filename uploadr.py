#!/usr/bin/env python

"""

    flickr-uploader designed for Synology Devices
    Upload a directory of media to Flickr to use as a backup to your local storage.

    Features:

    -Uploads both images and movies (JPG, PNG, GIF, AVI, MOV files)
    -Stores image information locally using a simple SQLite database
    -Automatically creates "Sets" based on the folder name the media is in
    -Ignores ".picasabackup" directory
    -Automatically removes images from Flickr when they are removed from your local hard drive
    
    Requirements:

    -Python 2.7+
    -File write access (for the token and local database)
    -Flickr API key (free)
    
    Setup:

    Go to http://www.flickr.com/services/apps/create/apply and apply for an API key Edit the following variables near the top in the script:

    FILES_DIR = "files/"
    FLICKR = { "title" : "", "description" : "", "tags" : "auto-upload", "is_public" : "0", "is_friend" : "0", "is_family" : "1" }
    SLEEP_TIME = 1 * 60
    DRIP_TIME = 1 * 60
    DB_PATH = os.path.join(FILES_DIR, "fickerdb")
    FLICKR["api_key"] = ""
    FLICKR["secret"] = ""
    Place the file uploadr.py in any directory and run:

    $ ./uploadr.py

    It will crawl through all the files from the FILES_DIR directory and begin the upload process.

    Upload files placed within a directory to your Flickr account.

   Inspired by:
        http://micampe.it/things/flickruploadr
        https://github.com/joelmx/flickrUploadr/blob/master/python3/uploadr.py

   Usage:

   cron entry (runs at the top of every hour )
   0  *  *   *   * /full/path/to/uploadr.py > /dev/null 2>&1

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.


"""
import sys
if sys.version_info < (2,7):
  sys.stderr.write("This script requires Python 2.7 or newer.\n")
  sys.stderr.write("Current version: " + sys.version + "\n")
  sys.stderr.flush()
  sys.exit(1)
  
import argparse
import hashlib
import mimetools
import mimetypes
import os
import shelve
import string
import time
import urllib
import urllib2
import webbrowser
import sqlite3 as lite
import pprint
import json
from xml.dom.minidom import parse
import hashlib
import fcntl
import errno
from sys import stdout
import itertools

#
##
##  Items you will want to change
##

#
# Location to scan for new files
#
FILES_DIR = ""
#
#   Flickr settings
#
FLICKR = {
        "title"                 : "",
        "description"           : "",
        "tags"                  : "auto-upload",
        "is_public"             : "0",
        "is_friend"             : "0",
        "is_family"             : "0" 
        }
#
#   How often to check for new files to upload (in seconds)
#
SLEEP_TIME = 1 * 60
#
#   Only with --drip-feed option:
#     How often to wait between uploading individual files (in seconds)
#
DRIP_TIME = 1 * 60
#
#   File we keep the history of uploaded files in.
#
DB_PATH = os.path.join(FILES_DIR, "fickerdb")

FLICKR["api_key"] = ""
FLICKR["secret"] = ""

##
##  You shouldn't need to modify anything below here
##

class APIConstants:
    """ APIConstants class
    """

    base = "http://api.flickr.com/services/"
    rest   = base + "rest/"
    auth   = base + "auth/"
    upload = base + "upload/"
    replace = base + "replace/"

    def __init__( self ):
       """ Constructor
       """
       pass

api = APIConstants()

class Uploadr:
    """ Uploadr class
    """

    token = None
    perms = ""
    TOKEN_FILE = os.path.join(FILES_DIR, "flickrToken")

    def __init__( self ):
        """ Constructor
        """
        self.token = self.getCachedToken()



    def signCall( self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = FLICKR[ "secret" ] + "api_key" + FLICKR[ "api_key" ] + foo
        #f = "api_key" + FLICKR[ "api_key" ] + foo
        return hashlib.md5( f ).hexdigest()

    def urlGen( self , base,data, sig ):
        """ urlGen
        """
        data['api_key'] = FLICKR[ "api_key" ]
        data['api_sig'] = sig
        encoded_url = base + "?" + urllib.urlencode( data )
        return encoded_url


    def authenticate( self ):
        """ Authenticate user so we can upload files
        """

        print("Getting new token")
        self.getFrob()
        self.getAuthKey()
        self.getToken()
        self.cacheToken()

    def getFrob( self ):
        """
        flickr.auth.getFrob

        Returns a frob to be used during authentication. This method call must be
        signed.

        This method does not require authentication.
        Arguments

        "api_key" (Required)
        Your API application key. See here for more details.
        """

        d = {
            "method"          : "flickr.auth.getFrob",
            "format"          : "json",
            "nojsoncallback"    : "1"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            response = self.getResponse( url )
            if ( self.isGood( response ) ):
                FLICKR[ "frob" ] = str(response["frob"]["_content"])
            else:
                self.reportError( response )
        except:
            print("Error getting frob:" + str( sys.exc_info() ))

    def getAuthKey( self ):
        """
        Checks to see if the user has authenticated this application
        """
        d =  {
            "frob"            : FLICKR[ "frob" ],
            "perms"           : "delete"
            }
        sig = self.signCall( d )
        url = self.urlGen( api.auth, d, sig )
        ans = ""
        try:
            webbrowser.open( url )
            ans = raw_input("Have you authenticated this application? (Y/N): ")
        except:
            print(str(sys.exc_info()))
        if ( ans.lower() == "n" ):
            print("You need to allow this program to access your Flickr site.")
            print("A web browser should pop open with instructions.")
            print("After you have allowed access restart uploadr.py")
            sys.exit()

    def getToken( self ):
        """
        http://www.flickr.com/services/api/flickr.auth.getToken.html

        flickr.auth.getToken

        Returns the auth token for the given frob, if one has been attached. This method call must be signed.
        Authentication

        This method does not require authentication.
        Arguments

        NTC: We need to store the token in a file so we can get it and then check it insted of
        getting a new on all the time.

        "api_key" (Required)
           Your API application key. See here for more details.
        frob (Required)
           The frob to check.
        """

        d = {
            "method"          : "flickr.auth.getToken",
            "frob"            : str(FLICKR[ "frob" ]),
            "format"          : "json",
            "nojsoncallback"    : "1"
        }
        sig = self.signCall( d )
        url = self.urlGen( api.rest, d, sig )
        try:
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                self.token = str(res['auth']['token']['_content'])
                self.perms = str(res['auth']['perms']['_content'])
                self.cacheToken()
            else :
                self.reportError( res )
        except:
            print(str(sys.exc_info()))

    def getCachedToken( self ):
        """
        Attempts to get the flickr token from disk.
       """
        if ( os.path.exists( self.TOKEN_FILE )):
            return open( self.TOKEN_FILE ).read()
        else :
            return None



    def cacheToken( self ):
        """ cacheToken
        """

        try:
            open( self.TOKEN_FILE , "w").write( str(self.token) )
        except:
            print("Issue writing token to local cache ", str(sys.exc_info()))

    def checkToken( self ):
        """
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        Authentication

        This method does not require authentication.
        Arguments

        "api_key" (Required)
            Your API application key. See here for more details.
        auth_token (Required)
            The authentication token to check.
        """

        if ( self.token == None ):
            return False
        else :
            d = {
                "auth_token"      :  str(self.token) ,
                "method"          :  "flickr.auth.checkToken",
                "format"          : "json",
                "nojsoncallback"  : "1"
            }
            sig = self.signCall( d )
            
            url = self.urlGen( api.rest, d, sig )
            try:
                res = self.getResponse( url )
                if ( self.isGood( res ) ):
                    self.token = res['auth']['token']['_content']
                    self.perms = res['auth']['perms']['_content']
                    return True
                else :
                    self.reportError( res )
            except:
                print(str(sys.exc_info()))
            return False

    def removeDeletedMedia( self ):
        """ Remove files deleted at the local source
        loop through database
        check if file exists
        if exists, continue
        if not exists, delete photo from fickr
        http://www.flickr.com/services/api/flickr.photos.delete.html
        """
        
        print "*****Removing deleted files*****"
        
        if ( not self.checkToken() ):
            self.authenticate()
        con = lite.connect(DB_PATH)
        
        with con:
            cur = con.cursor()    
            cur.execute("SELECT files_id, path FROM files")        
            rows = cur.fetchall()
            
            for row in rows:
                if( not os.path.isfile(row[1])):
                    success = self.deleteFile(row, cur)
        print "*****Completed deleted files*****"
    
    def upload( self ):
        """ upload
        """
        
        print "*****Uploading files*****"
        
        allMedia = self.grabNewFiles()
        print "Found " + str(len(allMedia)) + " files"
        for i, file in enumerate( allMedia ):
            success = self.uploadFile( file )
            if args.drip_feed and success and i != len( newFiles )-1:
                print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                time.sleep( DRIP_TIME )
        print "*****Completed uploading files*****"
    
        
    def grabNewFiles( self ): 
        """ grabNewFiles
        """

        files = []
        for dirpath, dirnames, filenames in os.walk( FILES_DIR, followlinks=True):
            if '.picasaoriginals' in dirnames:
                dirnames.remove('.picasaoriginals')
            for f in filenames :
                ext = f.lower().split(".")[-1]
                if ( ext == "jpg" or ext == "png"):
                #if ( ext == "jpg" or ext == "png" or ext == "avi" or ext == "mov" or ext == "mpg"):
                    files.append( os.path.normpath( dirpath + "/" + f ) )
        files.sort()
        return files

    def uploadFile( self, file ):
        """ uploadFile
        """

        success = False
        con = lite.connect(DB_PATH)
        fileMd5 = self.md5Checksum(file)
        with con:
            cur = con.cursor()    
            cur.execute("SELECT rowid,files_id,path,set_id,md5,tagged FROM files WHERE path = ?", (file,))        
            row = cur.fetchone()
            
            if(row is None):
                print("Uploading " + file + "...")
                head, setName = os.path.split(os.path.dirname(file))
                try:
                    photo = ('photo', file, open(file,'rb').read())
                    if args.title: # Replace
                        FLICKR["title"] = args.title
                    if args.description: # Replace
                        FLICKR["description"] = args.description
                    if args.tags: # Append
                        FLICKR["tags"] += " " + args.tags + " "
                    d = {
                        "auth_token"    : str(self.token),
                        "perms"         : str(self.perms),
                        "title"         : str( FLICKR["title"] ),
                        "description"   : str( FLICKR["description"] ),
                        "tags"          : str( FLICKR["tags"] + "," + setName ),
                        "is_public"     : str( FLICKR["is_public"] ),
                        "is_friend"     : str( FLICKR["is_friend"] ),
                        "is_family"     : str( FLICKR["is_family"] )
                    }
                    sig = self.signCall( d )
                    d[ "api_sig" ] = sig
                    d[ "api_key" ] = FLICKR[ "api_key" ]
                    url = self.build_request(api.upload, d, (photo,))
                    res = parse(urllib2.urlopen( url ))
                    if ( not res == "" and res.documentElement.attributes['stat'].value == "ok" ):
                        print("Successfully uploaded the file: " + file)
                        # Add to set
                    
                        cur.execute('INSERT INTO files (files_id, path, md5, tagged) VALUES (?, ?, ?, 1)',(int(str(res.getElementsByTagName('photoid')[0].firstChild.nodeValue)), file, self.md5Checksum(file)))
                        success = True
                    else :
                        print("A problem occurred while attempting to upload the file: " + file)
                        try:
                            print("Error: " + str( res.toxml() ))
                        except:
                            print("Error: " + str( res.toxml() ))
                except:
                    print(str(sys.exc_info()))
            elif(fileMd5 != str(row[4])):
                self.replacePhoto(file, row[1], fileMd5, cur, con);
            return success
                        
    def replacePhoto ( self, file, file_id, fileMd5, cur, con ) :
        success = False
        print("Replacing the file: " + file + "...")
        try:
            photo = ('photo', file, open(file,'rb').read())
    
            d = {
                "auth_token"    : str(self.token),
                "photo_id"     : str( file_id )
            }
            sig = self.signCall( d )
            d[ "api_sig" ] = sig
            d[ "api_key" ] = FLICKR[ "api_key" ]
            url = self.build_request(api.replace, d, (photo,))
            res = parse(urllib2.urlopen( url ))
            if ( not res == "" and res.documentElement.attributes['stat'].value == "ok" ):
                print("Successfully replaced the file: " + file)
                # Add to set
            
                cur.execute('UPDATE files SET md5 = ? WHERE files_id = ?',(fileMd5, file_id))
                con.commit()
                success = True
            else :
                print("A problem occurred while attempting to replace the file: " + file)
                try:
                    print("Error: " + str( res.toxml() ))
                except:
                    print("Error: " + str( res.toxml() ))
        except:
            print(str(sys.exc_info()))
        
        return success
    def deleteFile( self, file, cur ):
        success = False
        print "Deleting file: " + str(file[1])
        
        try:
            d = {
                "auth_token"      : str(self.token),
                "perms"           : str(self.perms),
                "format"          : "rest",
                "method"          : "flickr.photos.delete",
                "photo_id"        : str( file[0] ),
                "format"          : "json",
                "nojsoncallback"  : "1"
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                
                # Find out if the file is the last item in a set, if so, remove the set from the local db
                cur.execute("SELECT set_id FROM files WHERE files_id = ?", (file[0],))
                row = cur.fetchone()
                cur.execute("SELECT set_id FROM files WHERE set_id = ?", (file[0],))
                rows = cur.fetchall()
                if(len(rows) == 0):
                    print "File is the last of the set, deleting the set ID: " + str(row[0]) 
                    cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))
                
                # Delete file record from the local db
                cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],))
                print("Successful deletion.")
                success = True
            else :
                if( res['code'] == 1 ):
                    # File already removed from Flicker
                    cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],)) 
                else :
                    self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return success               

    def logSetCreation( self, setId, setName, primaryPhotoId, cur, con):
        print "adding set to log: " + str(setName)
        
        success = False
        cur.execute("INSERT INTO sets (set_id, name, primary_photo_id) VALUES (?,?,?)", (setId,setName,primaryPhotoId))        
        cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, primaryPhotoId)) 
        con.commit()
        return True

    def build_request(self, theurl, fields, files, txheaders=None):
        """
        build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html

        Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
        You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        """

        content_type, body = self.encode_multipart_formdata(fields, files)
        if not txheaders: txheaders = {}
        txheaders['Content-type'] = content_type
        txheaders['Content-length'] = str(len(body))

        return urllib2.Request(theurl, body, txheaders)

    def encode_multipart_formdata(self,fields, files, BOUNDARY = '-----'+mimetools.choose_boundary()+'-----'):
        """ Encodes fields and files for uploading.
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for urllib2.Request instance
        You can optionally pass in a boundary string to use or we'll let mimetools provide one.
        """

        CRLF = '\r\n'
        L = []
        if isinstance(fields, dict):
            fields = fields.items()
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % filetype)
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY        # XXX what if no files are encoded
        return content_type, body


    def isGood( self, res ):
        """ isGood
        """

        if ( not res == "" and res['stat'] == "ok" ):
            return True
        else :
            return False


    def reportError( self, res ):
        """ reportError
        """

        try:
            print("Error: " + str( res['code'] + " " + res['message'] ))
        except:
            print("Error: " + str( res ))

    def getResponse( self, url ):
        """
        Send the url and get a response.  Let errors float up
        """
        
        try:
            res = urllib2.urlopen( url ).read()
        except urllib2.HTTPError, e:
            print e.code
        except urllib2.URLError, e:
            print e.args 
        return json.loads(res)


    def run( self ):
        """ run
        """

        while ( True ):
            self.upload()
            print("Last check: " + str( time.asctime(time.localtime())))
            time.sleep( SLEEP_TIME )
    
    def createSets( self ):
        print('*****Creating Sets*****')
        
        con = lite.connect(DB_PATH)

        with con:    
    
            cur = con.cursor()    
            cur.execute("SELECT files_id, path, set_id FROM files")

            files = cur.fetchall()
        
            for row in files:
                head, setName = os.path.split(os.path.dirname(row[1]))
                newSetCreated = False
                
                cur.execute("SELECT set_id, name FROM sets WHERE name = ?", (setName,))
            
                set = cur.fetchone()
                
                if set == None:
                    setId = self.createSet(setName, row[0], cur, con)  
                    print "Created the set: " + setName
                    newSetCreated = True                  
                else :
                    setId = set[0]
                    
                if row[2] == None and newSetCreated == False :
                    print "adding file to set"
                    self.addFileToSet(setId, row, cur)
        print('*****Completed creating sets*****')
    
    def addFileToSet( self, setId, file, cur):
        try:
            d = {
                "auth_token"          : str(self.token),
                "perms"               : str(self.perms),
                "format"              : "json",
                "nojsoncallback"      : "1",
                "method"              : "flickr.photosets.addPhoto",
                "photoset_id"         : str( setId ),
                "photo_id"            : str( file[0] )
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
            
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
            
                print("Successfully added file to set.")
                
                cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, file[0]))        
                        
            else :
                if ( res['code'] == 1 ) :
                    print "Photoset not found, creating new set..."
                    head, setName = os.path.split(os.path.dirname(file[1]))
                    self.createSet( setName, file[0], cur)
                else :
                    self.reportError( res )
        except:
            print(str(sys.exc_info()))
            
        
    def createSet( self, setName, primaryPhotoId, cur, con):
        print "Creating new set: " + str(setName)
        
        try:
            d = {
                "auth_token"          : str(self.token),
                "perms"               : str(self.perms),
                "format"              : "json",
                "nojsoncallback"      : "1",
                "method"              : "flickr.photosets.create",
                "primary_photo_id"    : str( primaryPhotoId ),
                "title"               : setName
            
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
       
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                self.logSetCreation( res["photoset"]["id"], setName, primaryPhotoId, cur, con )
                return res["photoset"]["id"]
            else :
                print d
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return False
            
    def setupDB ( self ):
        print("Setting up the database")
        try:
            print DB_PATH
            con = lite.connect(DB_PATH)
            cur = con.cursor() 
            cur.execute('create table if not exists files (files_id int, path text, set_id int, md5 text, tagged int)')
            cur.execute('create table if not exists sets (set_id int, name text, primary_photo_id INTEGER)')
            con.commit()
            con.close()
        except lite.Error, e:
            print "Error %s:" % e.args[0]
            sys.exit(1)
        finally:
            if con:
                con.close()
                print("Completed database setup")
                
    def md5Checksum(self, filePath):
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest() 
    
    def addTagsToUploadedPhotos ( self ) :
        print('*****Adding tags to existing photos*****')
        
        con = lite.connect(DB_PATH)

        with con:    
    
            cur = con.cursor()    
            cur.execute("SELECT files_id, path, set_id, tagged FROM files")

            files = cur.fetchall()
            
            for row in files:
                if(row[3] != 1) :
                    head, setName = os.path.split(os.path.dirname(row[1]))
                    
                    status = self.addTagToPhoto(row, setName, cur, con)
                    
                    if status == False:
                        print "Error adding tag to file: " + file[1]
                                         
        print('*****Completed adding tags*****')
    
    def addTagToPhoto(self, file, tagName, cur, con) :
        print "Adding tag " + tagName + " to photo: " + str(file[1]) + " (" + str(file[0]) + ")"
        
        try:
            d = {
                "auth_token"          : str(self.token),
                "perms"               : str(self.perms),
                "format"              : "json",
                "nojsoncallback"      : "1",
                "method"              : "flickr.photos.addTags",
                "photo_id"          : str( file[0] ),
                "tags"               : tagName
            }
            sig = self.signCall( d )
            url = self.urlGen( api.rest, d, sig )
       
            res = self.getResponse( url )
            if ( self.isGood( res ) ):
                cur.execute("UPDATE files SET tagged=? WHERE files_id=?", (1, file[0]))
                con.commit()
                return True
            else :
                print d
                self.reportError( res )
        except:
            print(str(sys.exc_info()))
        return False
    
if __name__ == "__main__":
    # Ensure that only once instance of this script is running
    f = open ('lock', 'w')
    try: fcntl.lockf (f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        if e.errno == errno.EAGAIN:
            sys.stderr.write('[%s] Script already running.\n' % time.strftime ('%c') )
            sys.exit(-1)
        raise
    parser = argparse.ArgumentParser(description='Upload files to Flickr.')
    parser.add_argument('-d', '--daemon', action='store_true',
        help='Run forever as a daemon')
    parser.add_argument('-i', '--title',       action='store',
        help='Title for uploaded files')
    parser.add_argument('-e', '--description', action='store',
        help='Description for uploaded files')
    parser.add_argument('-t', '--tags',        action='store',
        help='Space-separated tags for uploaded files')
    parser.add_argument('-r', '--drip-feed',   action='store_true',
        help='Wait a bit between uploading individual files')
    args = parser.parse_args()

    flick = Uploadr()
    
    if FILES_DIR == "":
        print("Please configure the name of the folder in the script with media available to sync with Flickr.")
        sys.exit()    

    if FLICKR["api_key"] == "" or FLICKR["secret"] == "":
        print("Please enter an API key and secret in the script file (see README).")
        sys.exit()
    

        
    flick.setupDB()

    if args.daemon:
        flick.run()
    else:
        if ( not flick.checkToken() ):
            flick.authenticate()
        flick.upload()
        flick.removeDeletedMedia()
        flick.createSets()
        flick.addTagsToUploadedPhotos()