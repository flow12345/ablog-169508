import os
import re
import random
import hashlib
import hmac
from string import letters
import time

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.ext.db import metadata

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


secret = 'tadada123!!#*@#&$!'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def login_required(func):
    def login(self, *args, **kwargs):
        if not self.user:
            self.redirect('/login')
        else:
            func(self, *args, **kwargs)
    return login


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# blog stuf
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    user_name = db.StringProperty(required=True)
    likes = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog.html", p=self)


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def count_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id)
        return c.count()

    @classmethod
    def all_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id).order('-created')
        return c


class Like(db.Model):
    """ Database to store post likes """
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            return self.error(404)

        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if not post:
            return self.error(404)
        self.render("permalink.html", post=post, comments_count=comments_count,
                    comments=comments)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
            raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/dashboard')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/dashboard')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Dashboard(BlogHandler):
    """ Dashboard page handler """
    @login_required
    def get(self):
        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC limit 20")
        # self.render('dashboard.html', user = self.user.name, posts=posts)
        self.render('dashboard.html',  user_name=self.user.name, posts=posts)


class NewPost(BlogHandler):
    @login_required
    def get(self):
            self.render("newpost.html")

    @login_required
    def post(self):
        if not self.user:
            self.redirect('/blog')
            return

        user_id = self.user.key().id(),
        user_name = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(),
                     user_id=self.user.key().id(),
                     user_name=self.user.name,
                     subject=subject,
                     content=content)

            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class EditPostPage(BlogHandler):
    """ Edit Post page handler """
    @login_required
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC limit 20")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                error = "You do not have access to edit this post."
                self.render("dashboard.html", user=self.user.name,
                            posts=posts, error=error)
        else:
            error = "This post does not exist."
            self.render('dashboard.html', error=error)

    @login_required
    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:

            if post.user_id == self.user.key().id():

                if subject and content:
                    key = db.Key.from_path('Post', int(post_id),
                                           parent=blog_key())
                    post = db.get(key)
                    if post:
                        post.subject = subject
                        post.content = content
                        post.put()
                        self.redirect('/blog/%s' % post_id)
                    else:
                        error = "This post does not exist."
                        self.render("dashboard.html", user=self.user.name,
                                    posts=posts, error=error)
                else:
                    error = "You need title and content to update a post."
                    self.render("editpost.html", subject=subject,
                                content=content, error=error)
            else:
                    error = "You do not have access to edit this post."
                    self.render("dashboard.html", user=self.user.name,
                                posts=posts, error=error)
        else:
            error = "This post does not exist."
            self.render('front.html', error=error)


class DeletePostPage(BlogHandler):
    """ Delete Post page handler """
    @login_required
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post"
                            " ORDER BY created DESC limit 20")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            if post.user_id == self.user.key().id():
                post.delete()
                error = "Your post has been deleted."
                self.render("deletepost.html", error=error)
            else:
                error = "You do not have access to delete this post."
                self.render("dashboard.html", user=self.user.name,
                            posts=posts, error=error)
        else:
            error = "This post does not exist."
            self.render("dashboard.html", user=self.user.name,
                        posts=posts, error=error)


class NewComment(BlogHandler):
    """ New Comment handler """
    @login_required
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        comment = self.request.get('comment')
        post = post_id
        user_id = self.user.key().id()
        commentor = self.user.name

        if comment:
            c = Comment(comment=comment, post=post_id,
                        user_id=self.user.key().id(),
                        commentor=self.user.name)
            c.put()

            # A fix for datastore's Eventual Consistency
            time.sleep(0.1)
            self.redirect('/blog/%s' % post_id)

        else:
            self.redirect('/blog/%s' % post_id)



class EditComment(BlogHandler):
    """ Edit Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))

        # Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if comment and comment.user_id == self.user.key().id():
            self.render("editcomment.html", comment=comment.comment)
        else:
            error = "You cannot edit another users' comments."
            self.render("permalink.html", post=post,
                        comments_count=comments_count,
                        comments=comments, error=error)

    @login_required
    def post(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            # Retrieve comment information
            comments = Comment.all_by_post_id(post_id)
            comments_count = Comment.count_by_post_id(post_id)

            if comment.user_id == self.user.key().id():
                comment_content = self.request.get("comment")
                if comment_content:
                    comment.comment = comment_content
                    comment.put()
                    time.sleep(0.1)
                    self.redirect('/blog/%s' % post_id)
                else:
                    error = "Please enter a comment."
                    self.render(
                        "editcomment.html",
                        comment=comment.comment)
        else:
            error = "This comment does not exist."
            self.render("permalink.html", post=post,
                        comments_count=comments_count,
                        comments=comments, error=error)


class DeleteComment(BlogHandler):
    """ Delete Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))

        # Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if comment:
            if comment.user_id == self.user.key().id():
                comment.delete()
                error = "Your comment has been deleted."
                self.render("deletecomment.html", error=error)
            else:
                error = "You can only delete your own comment."
                self.render("permalink.html", post=post,
                            comments_count=comments_count,
                            comments=comments, error=error)
        else:
            error = "This comment does not exist."
            self.render("permalink.html", post=post,
                        comments_count=comments_count,
                        comments=comments, error=error)


class LikePost(BlogHandler):
    """ Like Comment handler """
    @login_required
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        user = self.user.key().id()

        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post:
            if post.user_id != user:
                like = Like.all().filter(
                    'post_id =', int(post_id)).filter('user_id =', user)
                if(like.get()):
                    like[0].delete()
                    post.likes = post.likes - 1
                    post.put()
                    self.redirect('/blog/%s' % post_id)
                else:
                    like = Like(post_id=int(post_id), user_id=user)
                    like.put()
                    post.likes = post.likes + 1
                    post.put()
                    self.redirect('/blog/%s' % post_id)
            else:
                error = "You cannot like your own post."
                self.render("permalink.html",  post=post,
                            comments_count=comments_count,
                            comments=comments, error=error)

        else:
            error = "This post does not exist."
            self.render("dashboard.html", user=self.user.name,
                        posts=posts, error=error)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', Register),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/dashboard', Dashboard),
                               ('/blog/edit/([0-9]+)', EditPostPage),
                               ('/blog/delete/([0-9]+)', DeletePostPage),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/blog/([0-9]+)/comment'
                                '/([0-9]+)/edit', EditComment),
                               ('/blog/([0-9]+)/comment'
                                '/([0-9]+)/delete', DeleteComment),
                               ('/blog/([0-9]+)/like', LikePost)
                               ],
                              debug=True)
