import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import matplotlib.dates as mdates
import math
from datetime import datetime, timedelta

x = []
y = []

def add_point(_x, _y):
    if(math.isnan(_x) or math.isnan(_y)):
        return
    global x, y
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
    plt.figure(figsize=(14, 10))
    plt.scatter(x, y, color='#f26043', s=80, label='Observed Points', alpha=0.8)  # Larger point size
    plt.plot(x, y_pred, color='red', linewidth=3, label='Fitted Line')  # Thicker line

    # Formatting the date on the x-axis
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())

    # Adding grid
    plt.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.7)

    # Adding labels and title with increased font size
    plt.xlabel('Time (seconds since epoch)', fontsize=18)
    plt.ylabel('Host relative timestamp in ms', fontsize=18)
    plt.title(f'Linear Regression Fit (R^2 score: {r2_score:.4f}, Slope: {slope:.4f})', fontsize=20)
    plt.legend(fontsize=16)

    # Rotating date labels for better readability
    plt.gcf().autofmt_xdate()

    # Setting background color for better contrast
    plt.gca().set_facecolor('#f7f7f7')

    # Setting tick parameters for larger text
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)

    print(f"R^2 score: {r2_score:.4f}, Slope: {slope:.4f}")
    plt.show()

# Example usage (add some points before plotting)
# add_point(1633035600, 120)
# add_point(1633122000, 130)
# add_point(1633208400, 125)
# add_point(1633294800, 135)
# plot()
