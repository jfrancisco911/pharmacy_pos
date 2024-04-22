from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_
from sqlalchemy import desc, func
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, Email
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from os.path import join, dirname, realpath
import os, uuid
import calendar



app = Flask(__name__)

#SqlAlchemy Database Configuration With Mysql
app.config['SECRET_KEY'] = 'Sample secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/pharmacy_pos'
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/images/')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#INITIALIZE MODELS
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    phone = db.Column(db.Integer)
    role = db.Column(db.String(255))
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    first_name = StringField('Firstname', validators=[InputRequired(), Length(max=255)], render_kw={"placeholder": "Firstname"})
    last_name = StringField('Lastname', validators=[InputRequired(), Length(max=255)], render_kw={"placeholder": "Lastname"})
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    role = StringField('Role', validators=[InputRequired(), Length(max=255)], render_kw={"placeholder": "Role"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(255))
    name = db.Column(db.String(255))
    supplier = db.Column(db.String(255))
    quantity = db.Column(db.Integer)
    category = db.Column(db.String(255))
    price = db.Column(db.Integer)
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))
    history = db.relationship('History', backref=db.backref('item', lazy=True))
    order_history = db.relationship('OrderHistory', backref=db.backref('item', lazy=True))
    status = db.Column(db.String(20), default='active')

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    supplier = db.Column(db.String(100), nullable=False)
    quantity_added = db.Column(db.Integer, nullable=False)
    stock_in_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))

class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    address = db.Column(db.String(255))
    phone = db.Column(db.String(255))
    email = db.Column(db.String(255))
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(255))
    lastname = db.Column(db.String(255))
    address = db.Column(db.String(255))
    phone = db.Column(db.String(255))
    email = db.Column(db.String(255))
    orders = db.relationship('Order', backref='customer', lazy=True)
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    total_amount = db.Column(db.Integer)
    order_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))
    history = db.relationship('OrderHistory', backref='order', lazy=True)

class OrderHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Integer)
    price = db.Column(db.Integer)
    order_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    created_by = db.Column(db.String(255))
    created_date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    updated_by = db.Column(db.String(255))
    updated_date = db.Column(db.DateTime(timezone=True))
#ENDS HERE ---------------------------------------------------------------

# FOR SERVING IMAGES IN FRONTEND
@app.route('/uploaded_img/<path:filename>', methods=['GET'])
def serve_uploaded_image(filename):
    return send_from_directory(directory=app.config['UPLOAD_FOLDER'], path=filename)
#ENDS HERE ---------------------------------------------------------------

#FOR SERVING LOGIN AND LOGOUT --------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'cashier':
                return redirect(url_for('cashier_dashboard'))
            else:
                flash('Invalid role for user')
        else:
            flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  
#ENDS HERE ---------------------------------------------------------------

# FOR SERVING ADMIN AND CASHIER
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    return render_template('admin_dashboard.html')

@app.route('/cashier/dashboard')
@login_required
def cashier_dashboard():
    if current_user.role != 'cashier':
        abort(403)
    return render_template('cashier_dashboard.html')
#ENDS HERE ---------------------------------------------------------------

# FOR SERVING CREATE USER AND ROLES
@app.route('/admin/users', methods=['POST', 'GET'])
@login_required
def users():
    form = RegisterForm()
    user_data = User.query.all()
    if request.method == 'POST':
 
        pass
    return render_template('admin_users.html', form=form, users=user_data)

@app.route('/admin/createUser', methods=['POST'])
@login_required
def createUser():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            role=form.role.data,
            created_by=current_user.username,
            created_date=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully")
        return redirect(url_for('users'))  # Redirect to the users route
    else:
        flash("Failed to create account. Please check the form for errors.")
        return redirect(url_for('users'))  # Redirect to the users route, or adjust the redirect URL as needed

@app.route('/update_roles/', methods=['POST'])
@login_required
def update_roles():
    if request.method == 'POST':
        if current_user.is_authenticated and current_user.role == 'admin':
            new_role = request.form.get('role')
            user_id = request.form.get('id')
            user = User.query.get(user_id)
            if user:
                user.role = new_role
                user.updated_by = current_user.username
                db.session.commit()
                flash("User role updated successfully")
                return redirect(url_for('users'))
            else:
                flash("User not found", 'error')
                return redirect(url_for('users'))
        else:
            flash("Unauthorized access", 'error')
            return redirect(url_for('users'))

@app.route('/deleteUser/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if request.method == 'POST':
        if current_user.is_authenticated and current_user.role == 'admin':
            user = User.query.get(id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash("User deleted successfully")
                return redirect(url_for('users'))
            else:
                flash("User not found", 'error')
                return redirect(url_for('users'))
        else:
            flash("Unauthorized access", 'error')
            return redirect(url_for('users'))
#ENDS HERE ---------------------------------------------------------------

#ROUTING FOR ADMIN INVENTORY --------------------------------------------------
@app.route('/admin/stockin', methods=['GET', 'POST'])
@login_required
def stockin():
    item_data = Item.query.filter_by(status='active').all()
    category_data = Category.query.all()
    supplier_data = Supplier.query.all()
    return render_template('admin_stockin.html', items = item_data, categories=category_data, supplier = supplier_data)

@app.route('/admin/archive')
@login_required
def item_archives():
    inactive_items = Item.query.filter_by(status='inactive').all()
    return render_template('admin_itemArchive.html', inactive_items=inactive_items)

@app.route('/admin/history/<int:id>', methods=['GET', 'POST'])
@login_required
def item_history(id):
    item = Item.query.get(id)
    history_data = History.query.filter_by(item_id=id).all()
    supplier_data = Supplier.query.all()

    for history in history_data:

        history.stock_in_date = history.stock_in_date.strftime("%Y-%m-%d %H:%M:%S")

    return render_template('admin_itemHistory.html', history=history_data, item=item, supplier = supplier_data)

@app.route('/admin/insertHistory', methods=['POST'])
@login_required
def insertHistory():
    if request.method == 'POST':
        item_id = request.form['item_id']
        supplier = request.form['supplier']
        quantity = int(request.form['quantity'])

        new_item = History(
            supplier=supplier.upper(),
            quantity_added=quantity,
            item_id=item_id,
            created_by=current_user.username
        )
        db.session.add(new_item)
        db.session.commit()

        item = Item.query.get(item_id)
        item.quantity = item.quantity + quantity
        db.session.commit()
        return redirect(url_for('item_history', id=item.id))

@app.route('/admin/insertItem', methods=['POST'])
@login_required
def insertItem():
    if request.method == 'POST':
        file = request.files['image']
        if file:
            filename = secure_filename(file.filename)
            file_name = str(uuid.uuid1()) + '_' + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_name))

        name = request.form['name']
        supplier = request.form['supplier']
        category = request.form['category']
        quantity = int(request.form['quantity'])
        price = request.form['price']

        existing_item = Item.query.filter_by(name=name.upper()).first()
        
        if existing_item:
            flash("Item Already Existed")
            return redirect(url_for('stockin'))
        else:
            new_item = Item(
                image_path=file_name,
                name=name.upper(),
                supplier=supplier.upper(),
                quantity=quantity,
                category=category.upper(),
                price=price,
                created_by=current_user.username
            )
            db.session.add(new_item)
            db.session.commit()

            new_history = History(
                supplier=new_item.supplier,
                quantity_added=new_item.quantity,
                item_id=new_item.id,
            )
            db.session.add(new_history)
            db.session.commit()

            flash("Item Successfully Added")
        return redirect(url_for('stockin'))

@app.route('/admin/activateItem/<int:id>', methods=['POST'])
@login_required
def activateItem(id):
    item = Item.query.get(id)
    if item:
        try:
            # Set the status of the item to active
            item.status = 'active'
            db.session.commit()
            flash("Item activated successfully")
        except Exception as e:
            flash(f"Error activating item: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
    else:
        flash("Item not found")
    
    return redirect(url_for('item_archives'))

@app.route('/admin/inactiveItem/<int:id>', methods=['POST'])
@login_required
def inactiveItem(id):
    item = Item.query.get(id)
    if item:
        try:
            # Set the status of the item to inactive
            item.status = 'inactive'  # Set status to 'inactive'
            db.session.commit()
            flash("Item marked as inactive successfully")
        except Exception as e:
            flash(f"Error marking item as inactive: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
    else:
        flash("Item not found")
    
    return redirect(url_for('stockin'))

@app.route('/admin/updateItem/<int:id>', methods=['POST'])
@login_required
def updateItem(id):
    item_id = request.form.get('id')
    item = Item.query.get(item_id)
    if item:
        try:
            new_price = request.form.get('new_price')
            if new_price and float(new_price) > 0:
                item.price = float(new_price)
                item.updated_by = current_user.username
                item.updated_date = datetime.now()
                db.session.commit()
                flash("Item Price Updated Successfully")
            else:
                flash("Invalid price. Please provide a valid positive number.")
        except ValueError:
            flash("Invalid price format. Please provide a valid number.")
            db.session.rollback()
        except Exception as e:
            flash(f"Error updating item price: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
    else:
        flash("Item not found")
    return redirect(url_for('stockin'))
#ENDS HERE ----------------------------------------------------

#ROUTING FOR ADMIN CATEGORY ------------------------------------------
@app.route('/admin/category', methods=['GET', 'POST'])
@login_required
def category():
    category_data = Category.query.all()
    return render_template('admin_category.html', category=category_data)

@app.route('/admin/addCategory', methods=['POST'])
@login_required
def addCategory():
    category_name = request.form.get('category_name')

    if not category_name:
        flash("Category name cannot be empty")
        return redirect(request.referrer)

    existing_category = Category.query.filter_by(name=category_name.upper()).first()
    if existing_category:
        flash("Category with the same name already exists")
        return redirect(request.referrer)

    new_category = Category(name=category_name.upper())
    try:
        new_category.created_by = current_user.username
        db.session.add(new_category)
        db.session.commit()
        flash("Category added successfully")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding category: {str(e)}")
    finally:
        db.session.close()

    return redirect(url_for('category'))

@app.route('/admin/deleteCategory/<int:id>', methods=['POST'])
@login_required
def deleteCategory(id):
    category = Category.query.get(id)
    if not category:
        flash("Category not found")
        return redirect(url_for('category'))

    try:
        db.session.delete(category)
        db.session.commit()
        flash("Category deleted successfully")
    except Exception as e:
        flash(f"Error deleting category: {str(e)}")
        db.session.rollback()
    finally:
        db.session.close()

    return redirect(url_for('category'))

@app.route('/admin/updateCategory/<int:id>', methods=['POST'])
@login_required
def updateCategory(id):
    category_data = Category.query.get_or_404(id)
    new_category_name = request.form.get('name')

    if not new_category_name:
        flash("Invalid category name")
        return redirect(url_for('category'))

    try:
        category_data.name = new_category_name.upper()
        category_data.updated_by = current_user.username
        category_data.updated_date = datetime.now()
        db.session.commit()
        flash("Category Updated Successfully")
    except Exception as e:
        flash(f"Error updating category: {str(e)}")
        db.session.rollback()
    finally:
        db.session.close()

    return redirect(url_for('category'))
#ENDS HERE ----------------------------------------------------

#ROUTING FOR ADMIN SUPPLIER ------------------------------------------
@app.route('/admin/supplier', methods=['GET', 'POST'])
@login_required
def supplier():
    supplier_data = Supplier.query.all()
    return render_template('admin_supplier.html', supplier=supplier_data)

@app.route('/admin/addSupplier', methods=['POST'])
@login_required
def addSupplier():
    supplier_name = request.form.get('supplier_name')
    supplier_address = request.form.get('supplier_address')
    supplier_phone = request.form.get('supplier_phone')
    supplier_email = request.form.get('supplier_email')

    existing_supplier = Supplier.query.filter_by(
        name=supplier_name.upper()).first()
    if existing_supplier:
        flash("Supplier with the same name already exists")
        return redirect(url_for('supplier'))

    new_supplier = Supplier(name=supplier_name.upper(),
                            address=supplier_address.upper(), 
                            phone=supplier_phone.upper(),
                            email=supplier_email.upper(),
                            created_by=current_user.username)
    try:
        db.session.add(new_supplier)
        db.session.commit()
        flash("Supplier added successfully")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding supplier: {str(e)}")
    finally:
        db.session.close()
    return redirect(url_for('supplier'))

@app.route('/admin/updateSupplier', methods=['POST'])
@login_required
def updateSupplier():
    supplier_id = request.form.get('id')
    supplier = Supplier.query.get(supplier_id)

    if not supplier:
        flash("Supplier not found")
        return redirect(url_for('supplier'))

    # Get updated information from the form
    supplier_name = request.form.get('name').upper()
    supplier_address = request.form.get('address').upper()
    supplier_phone = request.form.get('phone').upper()
    supplier_email = request.form.get('email').upper()

    supplier.name = supplier_name
    supplier.address = supplier_address
    supplier.phone = supplier_phone
    supplier.email = supplier_email
    supplier.updated_by = current_user.username
    supplier.updated_date = datetime.now()
    try:
        db.session.commit()
        flash("Supplier information updated successfully")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating supplier information: {str(e)}")
    finally:
        db.session.close()

    return redirect(url_for('supplier'))

@app.route('/admin/deleteSupplier/<int:id>', methods=['POST'])
@login_required
def deleteSupplier(id):
    name = Supplier.query.get(id)
    if name:
        try:
            db.session.delete(name)
            db.session.commit()
            flash("Supplier Deleted Successfully")
        except Exception as e:
            flash(f"Error deleting Su: {str(e)}")
            db.session.rollback()
        finally:
            db.session.close()
    else:
        flash("Supplier not found")  
    return redirect(url_for('supplier'))
#ENDS HERE ----------------------------------------------------

#ROUTING FOR CUSTOMER -----------------------------------------
@app.route('/admin/customer', methods=['GET', 'POST'])
@login_required
def customer():
    customer_Data = Customer.query.all()
    return render_template('admin_customer.html', customer=customer_Data)
#ENDS HERE ----------------------------------------------------

#ROUTING FOR ADMIN ORDER HISTORY AND ORDER DETAILS-------------
@app.route('/admin/order_history/<int:id>', methods=['GET'])
@login_required
def order_history(id):
    customer = Customer.query.get(id)
    if customer is None:
        abort(404)  # Customer not found, return 404 error
    orders = customer.orders
    return render_template('admin_orderHistory.html', customer=customer, orders=orders)

@app.route('/admin/order_details/<int:id>', methods=['GET'])
@login_required
def order_details(id):
    history = OrderHistory.query.filter_by(order_id=id)
    order = Order.query.get(id)
    customer = Customer.query.filter_by(id=order.customer_id).first()
    if order is None:
        abort(404)  # Order not found, return 404 error
    return render_template('admin_orderDetails.html', history=history, order=order, customer=customer)
#ENDS HERE ----------------------------------------------------

#ROUTING FOR SALES REPORT -----------------------------------------
@app.route('/admin/sales_report', methods=['GET', 'POST'])
@login_required
def sales_report():
    annual_sales = calculate_annual_sales()

    monthly_sales = calculate_monthly_sales()

    weekly_sales = calculate_weekly_sales()

    return render_template('admin_sales.html', annual_sales=annual_sales, monthly_sales=monthly_sales, weekly_sales=weekly_sales)

def calculate_annual_sales():
    # Calculate annual sales for the current year
    current_year = datetime.now().year
    start_date = datetime(current_year, 1, 1)
    end_date = datetime(current_year, 12, 31)
    annual_sales = db.session.query(func.sum(Order.total_amount)).filter(Order.order_date.between(start_date, end_date)).scalar()
    return annual_sales or 0

def calculate_monthly_sales():
    # Calculate monthly sales for the current month
    current_date = datetime.now()
    start_date = current_date.replace(day=1)
    end_date = current_date.replace(day=calendar.monthrange(current_date.year, current_date.month)[1])
    monthly_sales = db.session.query(func.sum(Order.total_amount)).filter(Order.order_date.between(start_date, end_date)).scalar()
    return monthly_sales or 0

def calculate_weekly_sales():
    # Calculate weekly sales for the current week
    current_date = datetime.now()
    start_date = current_date - timedelta(days=current_date.weekday())
    end_date = start_date + timedelta(days=6)
    weekly_sales = db.session.query(func.sum(Order.total_amount)).filter(Order.order_date.between(start_date, end_date)).scalar()
    return weekly_sales or 0

@app.route('/admin/item_sales', methods=['GET', 'POST'])
@login_required
def item_sales():
    if request.method == 'POST':
        start_date_str = request.form.get('start_date', '')
        end_date_str = request.form.get('end_date', '')

        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

                item_sales_data = {}

                # Query orders within the date range
                orders = Order.query.filter(Order.order_date.between(start_date, end_date)).all()

                # Process orders and calculate item sales data
                for order in orders:
                    for order_history in order.history:
                        item_id = order_history.item_id
                        item = Item.query.get(item_id)

                        if item_id not in item_sales_data:
                            item_sales_data[item_id] = {
                                'item': item,
                                'quantity': order_history.quantity,
                                'total': order_history.quantity * order_history.price,
                            }
                        else:
                            item_sales_data[item_id]['quantity'] += order_history.quantity
                            item_sales_data[item_id]['total'] += order_history.quantity * order_history.price

                # Calculate overall total
                overall_total = sum(item['total'] for item in item_sales_data.values())

                # Render the template with item sales data
                return render_template('admin_sales.html', item_sales_data=item_sales_data, overall_total=overall_total)

            except ValueError:
                flash('Invalid date format. Please enter dates in the format YYYY-MM-DD.', 'error')
                return redirect(url_for('sales_report'))

        else:
            flash('Please provide both start date and end date.', 'error')
            return redirect(url_for('sales_report'))

    # For GET requests, redirect to sales route
    return redirect(url_for('sales_report'))
#ENDS HERE ----------------------------------------------------

#ROUTING FOR CASHIER ITEMLIST AND ADD TO CART -----------------
@app.route('/cashier/item_list')
@login_required
def item_list():
    if current_user.role == 'cashier':
        item_data = Item.query.filter_by(status='active').all()
        category_data = Category.query.all()

    return render_template('cashier_itemList.html', items=item_data, categories=category_data)

@app.route('/cashier/cart', methods=['GET', 'POST'])
@login_required
def cart():
    if current_user.role == 'cashier':
        customers = Customer.query.all()
        cart_items = session.get('cart', [])

        return render_template('cashier_cart.html', customers=customers, cart_items=cart_items)

@app.route('/cashier/addToCart/<int:item_id>', methods=['POST'])
@login_required
def addToCart(item_id):
    if current_user.role == 'cashier':
        item_id = int(item_id)
        item = Item.query.get(item_id)

        if item is None:
            flash('Item not found!', 'error')
            return redirect(url_for('itemList'))
        
        # Check if the item's quantity is greater than 0 before adding it to the cart
        if item.quantity <= 0:
            flash('Item quantity is 0, cannot add to cart!', 'error')
            return redirect(url_for('itemList'))

        if 'cart' not in session:
            session['cart'] = []

        for cart_item in session['cart']:
            if cart_item['item_id'] == item_id:
                cart_item['quantity'] += 1
                flash('Item quantity increased in cart!', 'info')
                return redirect(url_for('item_list'))

        session['cart'].append({
            'item_id': item.id,
            'name': item.name,
            'price': item.price,
            'quantity': 1
        })

        flash('Item added to cart successfully!', 'success')
        return redirect(url_for('item_list'))


@app.route('/cashier/deleteToCart/<int:item_id>', methods=['GET'])
@login_required
def deleteToCart(item_id):
    if current_user.role == 'cashier':
        
        item_id = int(item_id)
        
        if 'cart' not in session:
            flash('Cart is empty!', 'error')
            return redirect(url_for('cart'))

        for index, cart_item in enumerate(session['cart']):
            if cart_item['item_id'] == item_id:
         
                del session['cart'][index]
                flash('Item removed from cart successfully!', 'success')
                break
        else:
            flash('Item not found in cart!', 'error')

        return redirect(url_for('cart'))

@app.route('/cashier/order', methods=['GET', 'POST'])
@login_required
def create_order():
    if current_user.role == 'cashier':
        if request.method == 'POST':
            customer_id = request.form.get('customer_id')
            items = session.get('cart', [])
            
            customer = Customer.query.get(customer_id)
            total_amount = sum(item['price'] * item['quantity'] for item in items)
            
            order = Order(
                customer_id=customer.id,
                total_amount=total_amount,
                order_date=datetime.utcnow()
            )
            db.session.add(order)
            db.session.commit()
            
            # Update item quantities and create order history
            for item in items:
                # Get the item from the database
                db_item = Item.query.get(item['item_id'])
                # Update the item quantity in the database
                db_item.quantity -= item['quantity']
                # Create order history
                new_history = OrderHistory(
                    order_id=order.id,
                    customer_id=customer.id,
                    item_id=item['item_id'],
                    quantity=item['quantity'],
                    price=item['price'],
                    order_date=datetime.utcnow(),
                    created_by=current_user.username
                )
                db.session.add(new_history)
            
            db.session.commit()
            session.pop('cart', None)
            flash('Order placed successfully!', 'success')
            return redirect(url_for('cart'))

    customers = Customer.query.all()
    items = Item.query.all()  # Retrieve all items
    return render_template('cashier_cart.html', customers=customers, items=items)
#ENDS HERE ----------------------------------------------------

#ROUTING FOR CASHIER CUSTOMER-------------------------------------
@app.route('/cashier/customers')
@login_required
def customers():
    if current_user.role == 'cashier':
        customer_data = Customer.query.all()

    return render_template('cashier_customer.html', customer=customer_data)

@app.route('/cashier/addCustomer', methods=['GET', 'POST'])
@login_required
def addCustomer():
    if current_user.role == 'cashier':
        if request.method == 'POST':
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            address = request.form.get('address')
            phone = request.form.get('phone')
            email = request.form.get('email')

            new_customer = Customer(
                firstname=firstname.upper(), 
                lastname=lastname.upper(), 
                address=address.upper(), 
                phone=phone.upper(), 
                email=email.upper(),
                created_by=current_user.username)
            
            db.session.add(new_customer)
            db.session.commit()

            flash('Customer added successfully!', 'success')

            return redirect(url_for('customers'))
    
    return render_template('cashier_customer.html')  

@app.route('/cashier/updateCustomer/<int:id>', methods=['GET', 'POST'])
@login_required
def updateCustomer(id):
    customer = Customer.query.get_or_404(id)

    if request.method == 'POST':
        customer.firstname = request.form.get('firstname').upper()
        customer.lastname = request.form.get('lastname').upper()
        customer.address = request.form.get('address').upper()
        customer.phone = request.form.get('phone').upper()
        customer.email = request.form.get('email').upper()
        customer.updated_by = current_user.username
        customer.updated_date = datetime.utcnow()
        
        db.session.commit()

        flash('Customer updated successfully!', 'success')

        # Redirect to the 'customers' route after updating
        return redirect(url_for('customers'))

    # Handle GET request (display form)
    return render_template('update_customer.html')

@app.route('/cashier/deleteCustomer/<int:id>', methods=['POST'])
@login_required
def deleteCustomer(id):
    if current_user.role == 'cashier':
        customer = Customer.query.get_or_404(id)
        db.session.delete(customer)
        db.session.commit()
        flash('Customer deleted successfully!', 'success')
    return redirect(url_for('customers'))
#ENDS HERE ----------------------------------------------------

#Automatic creation of tables in the database in mysql
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
