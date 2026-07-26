struct pt { int x, y; };
long dist2(struct pt a, struct pt b){ long dx=a.x-b.x, dy=a.y-b.y; return dx*dx+dy*dy; }
int rect_area(const struct pt *p){ return (p[1].x-p[0].x)*(p[1].y-p[0].y); }
