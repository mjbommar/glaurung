struct node { struct node *next; int val; };
int list_sum(const struct node *h){ int s=0; while(h){ s+=h->val; h=h->next; } return s; }
struct node *list_find(struct node *h,int v){ while(h){ if(h->val==v) return h; h=h->next; } return 0; }
