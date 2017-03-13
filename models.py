import webapp2
from google.appengine.ext import db

from jinja_env import jinja_env


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.EmailProperty()
    registered_datetime = db.DateTimeProperty(auto_now_add=True)


class BlogPost(db.Model):
    author = db.ReferenceProperty(User)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def from_string_id(cls, blog_post_id):
        return BlogPost.get_by_id(int(blog_post_id))

    def get_likes(self):
        return Like.all().filter('post =', self)

    def render(self, **kwargs):
        likes = Like.all().filter('post =', self).fetch(None)
        template = jinja_env.get_template("blogpost.html")
        return template.render(bp=self, likes=self.get_likes().fetch(None),
                               **kwargs)

    def uri_for(self, action='post-view'):
        return webapp2.uri_for(action, post=str(self.key().id()))


class Like(db.Model):
    post = db.ReferenceProperty(BlogPost)
    author = db.ReferenceProperty(User)
    clicked_on = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):
    blog_post = db.ReferenceProperty(BlogPost)
    author = db.ReferenceProperty(User)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(required=True, auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        return jinja_env.get_template('comment.html').render(comment=self)

    def uri_for(self, action='comment-edit'):
        return webapp2.uri_for(action,
                               post=str(self.blog_post.key().id()),
                               comment=str(self.key().id()))