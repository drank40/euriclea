package main

import (
    "gonum.org/v1/plot"
    "gonum.org/v1/plot/plotter"
    "gonum.org/v1/plot/vg"
    "errors"
)

var x = []uint64{}
var y = []uint64{}

func add_point(_x uint64, _y uint64) {
    x = append(x, _x)
    y = append(y, _y)
}

func test_plot() (error) {
    // Create a new plot, setting the title and labels

    if(len(x) != len(y)) {
        return errors.New("x and y arrays must be of the same size")
    }

    l := len(x)

    p := plot.New()
    p.Title.Text = "My Simple Plot"
    p.X.Label.Text = "X"
    p.Y.Label.Text = "Y"

    // Create some fake data
    pts := make(plotter.XYs, l)
    for i := range pts {
        pts[i].X = float64(x[i])
        pts[i].Y = float64(y[i]) // Example function: y = x^2
    }

    // Make a line plotter and add it to the plot
    line, err := plotter.NewScatter(pts)
    if err != nil {
        return err
    }
    p.Add(line)

    if err := p.Save(10*vg.Inch, 10*vg.Inch, "plot.png"); err != nil {
        return err
    }

    return nil
}
