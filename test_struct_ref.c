struct Test
{
    int c;
};

int main()
{
    int b = 0;
    struct Test t, *a, **p2, ***p3;

    (++(*(a + b)))->c;
    ((*(a + b))++)->c;
    (a + b)->c;
    (*(a + b)).c;
    (*(p2 + b))->c;
    (*(&(*(a + b)))).c;
    (&(*(a + b)))->c;

    (a[b]).c;       
    (p2[b])->c;      
    (*(p2[b])).c;    
    (*(p3[b]))->c;   
    (&(a[b]))->c;   
    (*(&(a[b]))).c; 
    (*(&(p2[b])))->c;
    (&(*(p2[b])))->c;

    t.c;
    a->c;
    (*a).c;
    (*p2)->c;
    (&t)->c;
}
