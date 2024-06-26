import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import matplotlib.dates as mdates
import math
from datetime import datetime, timedelta
from plotter import *

x = []
y = []

def add_point(_x, _y):
    if(math.isnan(_x) or math.isnan(_y)):
        return
    global x,y
    x.append(_x)
    y.append(_y)

def plot():
    global x, y
    # First ensure that x is in the correct format
    if isinstance(x[0], int):  # Assuming all elements are of the same type
        x = [datetime(1970, 1, 1) + timedelta(seconds=sec) for sec in x]

    # Convert datetime objects to seconds since epoch for model fitting
    x_seconds = np.array([(dt - datetime(1970, 1, 1)).total_seconds() for dt in x]).reshape(-1, 1)
    y = np.array(y).reshape(-1, 1)

    # Perform linear regression on the new points
    model = LinearRegression()
    model.fit(x_seconds, y)
    y_pred = model.predict(x_seconds)

    # Compute linearity
    r2_score = model.score(x_seconds, y)
    slope = model.coef_[0][0]  # Assuming it's a 1D regression

    # Setup the plot
    plt.figure(figsize=(10, 6))
    plt.scatter(x, y, color='blue', label='Observed Points')
    plt.plot(x, y_pred, color='red', label='Fitted Line')

    # Formatting the date on the x-axis
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())

    plt.xlabel('Time (seconds since epoch)')
    plt.ylabel('Y')
    plt.legend()
    plt.title(f'Linear Regression Fit (R^2 score: {r2_score:.4f})')
    plt.gcf().autofmt_xdate()  # Rotate date labels for better readability
    print(f"R^2 score: {r2_score:.4f}, Slope: {slope:.4f}")
    plt.show()
