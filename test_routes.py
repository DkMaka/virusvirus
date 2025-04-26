# This file adds test routes to verify Railway deployment
# Import this at the top of your app.py file:
# from test_routes import add_test_routes

def add_test_routes(app):
    @app.route('/railway-test')
    def railway_test():
        return render_template('railway_test.html')
        
    @app.route('/api/status')
    def api_status():
        return {'status': 'ok', 'message': 'Railway deployment is working!'}