from flask import Flask
from healthcheck import HealthCheck

app = Flask(__name__)

health = HealthCheck()


# add your own check function to the healthcheck
def logger_available():
    return True, "OK"


health.add_check(logger_available)

app.add_url_rule("/healthcheck", "healthcheck", view_func=health.run)
