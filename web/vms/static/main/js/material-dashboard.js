(function() {
    isWindows = navigator.platform.indexOf('Win') > -1 ? true : false;

    if (isWindows) {
        $('.sidebar .sidebar-wrapper, .main-panel').perfectScrollbar();
        $('html').addClass('perfect-scrollbar-on');
    } else {
        $('html').addClass('perfect-scrollbar-off');
    }
    $('html').addClass('perfect-scrollbar-off');
})();

function topFunction() {
    document.body.scrollTop = 0;
    document.documentElement.scrollTop = 0;
}


var searchVisible = 0;
var transparent = true;

var transparentDemo = true;
var fixedTop = false;

var mobile_menu_visible = 0,
    mobile_menu_initialized = false,
    toggle_initialized = false,
    bootstrap_nav_initialized = false;

var seq = 0,
    delays = 80,
    durations = 500;
var seq2 = 0,
    delays2 = 80,
    durations2 = 500;


$(document).ready(function() {

    $sidebar = $('.sidebar');

    $.material.init();

    window_width = $(window).width();

    md.initSidebarsCheck();

    md.checkSidebarImage();

    $('[rel="tooltip"]').tooltip();

    $('.form-control').on("focus", function() {
        $(this).parent('.input-group').addClass("input-group-focus");
    }).on("blur", function() {
        $(this).parent(".input-group").removeClass("input-group-focus");
    });

});

$(document).on('click', '.navbar-toggle', function() {
    $toggle = $(this);

    if (mobile_menu_visible == 1) {
        $('html').removeClass('nav-open');

        $('.close-layer').remove();
        setTimeout(function() {
            $toggle.removeClass('toggled');
        }, 400);

        mobile_menu_visible = 0;
    } else {
        setTimeout(function() {
            $toggle.addClass('toggled');
        }, 430);

        div = '<div id="bodyClick"></div>';
        $(div).appendTo('body').click(function() {
            $('html').removeClass('nav-open');
            mobile_menu_visible = 0;
            setTimeout(function() {
                $toggle.removeClass('toggled');
                $('#bodyClick').remove();
            }, 550);
        });

        $('html').addClass('nav-open');
        mobile_menu_visible = 1;

    }
});

$(window).resize(function() {
    md.initSidebarsCheck();
    seq = seq2 = 0;
});

md = {
    misc: {
        navbar_menu_visible: 0,
        active_collapse: true,
        disabled_collapse_init: 0,
    },

    checkSidebarImage: function() {
        $sidebar = $('.sidebar');
        image_src = $sidebar.data('image');

        if (image_src !== undefined) {
            sidebar_container = '<div class="sidebar-background" style="background-image: url(' + image_src + ') "/>'
            $sidebar.append(sidebar_container);
        }
    },

    checkScrollForTransparentNavbar: debounce(function() {
        if ($(document).scrollTop() > 260) {
            if (transparent) {
                transparent = false;
                $('.navbar-color-on-scroll').removeClass('navbar-transparent');
            }
        } else {
            if (!transparent) {
                transparent = true;
                $('.navbar-color-on-scroll').addClass('navbar-transparent');
            }
        }
    }, 17),

    initSidebarsCheck: function() {
        if ($(window).width() <= 991) {
            if ($sidebar.length != 0) {
                md.initRightMenu();
            }
        }
    },

    initRightMenu: debounce(function() {
        $sidebar_wrapper = $('.sidebar-wrapper');

        if (!mobile_menu_initialized) {
            $navbar = $('nav').find('.navbar-collapse').children('.navbar-nav.navbar-right');

            mobile_menu_content = '';

            nav_content = $navbar.html();

            nav_content = '<ul class="nav nav-mobile-menu">' + nav_content + '</ul>';


            $sidebar_nav = $sidebar_wrapper.find(' > .nav');

            $nav_content = $(nav_content);
            $nav_content.insertBefore($sidebar_nav);

            $(".sidebar-wrapper .dropdown .dropdown-menu > li > a").click(function(event) {
                event.stopPropagation();

            });

            window.dispatchEvent(new Event('resize'));

            mobile_menu_initialized = true;
        } else {
            if ($(window).width() > 991) {
                $sidebar_wrapper.find('.navbar-form').remove();
                $sidebar_wrapper.find('.nav-mobile-menu').remove();

                mobile_menu_initialized = false;
            }
        }
    }, 200),


    startAnimationForLineChart: function(chart) {

        chart.on('draw', function(data) {
            if (data.type === 'line' || data.type === 'area') {
                data.element.animate({
                    d: {
                        begin: 600,
                        dur: 700,
                        from: data.path.clone().scale(1, 0).translate(0, data.chartRect.height()).stringify(),
                        to: data.path.clone().stringify(),
                        easing: Chartist.Svg.Easing.easeOutQuint
                    }
                });
            } else if (data.type === 'point') {
                seq++;
                data.element.animate({
                    opacity: {
                        begin: seq * delays,
                        dur: durations,
                        from: 0,
                        to: 1,
                        easing: 'ease'
                    }
                });
            }
        });

        seq = 0;
    },
    startAnimationForBarChart: function(chart) {

        chart.on('draw', function(data) {
            if (data.type === 'bar') {
                seq2++;
                data.element.animate({
                    opacity: {
                        begin: seq2 * delays2,
                        dur: durations2,
                        from: 0,
                        to: 1,
                        easing: 'ease'
                    }
                });
            }
        });

        seq2 = 0;
    }
}


function debounce(func, wait, immediate) {
    var timeout;
    return function() {
        var context = this,
            args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        }, wait);
        if (immediate && !timeout) func.apply(context, args);
    };
};

function showNotification(from, align, text, boxType) {

    $.notify({
        icon: "notifications",
        message: text

    }, {
        type: boxType,
        timer: 3000,
        placement: {
            from: from,
            align: align
        }
    });
}
